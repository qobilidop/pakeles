//! Bounded external-command execution shared by generators and conformance
//! oracles. Child output is drained concurrently, retained up to a fixed cap,
//! and the whole Unix process group is terminated when a deadline expires.

use anyhow::{bail, Context, Result};
use std::io::{Read, Write};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
pub struct ProcessLimits {
    pub timeout: Duration,
    /// Maximum retained bytes for each of stdout and stderr. Pipes continue to
    /// be drained after the cap so a noisy child cannot deadlock.
    pub max_output_bytes_per_stream: usize,
}

impl Default for ProcessLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(120),
            max_output_bytes_per_stream: 8 * 1024 * 1024,
        }
    }
}

#[derive(Debug)]
pub struct ProcessOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

fn prepare(command: &mut Command) {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
}

/// Spawn a command in its own process group. Call [`terminate`] instead of
/// `Child::kill` so descendants do not survive a timed-out parent.
pub fn spawn_grouped(command: &mut Command) -> Result<Child> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    command.spawn().context("spawning external command")
}

/// Best-effort termination followed by a mandatory reap.
pub fn terminate(child: &mut Child) {
    #[cfg(unix)]
    // SAFETY: `child.id()` is a live child PID and the negated PID targets the
    // process group created by `process_group(0)`. Failure is handled by the
    // direct-child fallback below.
    unsafe {
        let _ = libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// How long a drain may outlive a terminated process group before we
/// stop waiting on it.
const GRACE: Duration = Duration::from_secs(5);

/// `JoinHandle::join`, but never past `deadline`. `None` means the
/// thread is still blocked — the caller must not wait for it.
fn finish_by<T>(
    handle: std::thread::JoinHandle<T>,
    deadline: Instant,
) -> Option<std::thread::Result<T>> {
    let mut poll = Duration::from_millis(1);
    while !handle.is_finished() {
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(poll);
        poll = (poll * 2).min(Duration::from_millis(20));
    }
    Some(handle.join())
}

fn read_bounded(mut reader: impl Read, limit: usize) -> std::io::Result<(Vec<u8>, bool)> {
    let mut retained = Vec::with_capacity(limit.min(64 * 1024));
    let mut truncated = false;
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let available = limit.saturating_sub(retained.len());
        let keep = read.min(available);
        retained.extend_from_slice(&buffer[..keep]);
        truncated |= keep < read;
    }
    Ok((retained, truncated))
}

pub fn run(command: &mut Command, limits: ProcessLimits) -> Result<ProcessOutput> {
    run_with_input(command, None, limits)
}

pub fn run_with_input(
    command: &mut Command,
    input: Option<Vec<u8>>,
    limits: ProcessLimits,
) -> Result<ProcessOutput> {
    prepare(command);
    if input.is_some() {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }
    let program = command.get_program().to_string_lossy().into_owned();
    let mut child = command
        .spawn()
        .with_context(|| format!("spawning {program}"))?;
    let stdout = child.stdout.take().context("child stdout pipe missing")?;
    let stderr = child.stderr.take().context("child stderr pipe missing")?;
    let cap = limits.max_output_bytes_per_stream;
    let stdout_reader = std::thread::spawn(move || read_bounded(stdout, cap));
    let stderr_reader = std::thread::spawn(move || read_bounded(stderr, cap));
    let mut stdin_writer = input.map(|input| {
        let mut stdin = child.stdin.take().expect("piped child stdin");
        std::thread::spawn(move || stdin.write_all(&input))
    });

    let deadline = Instant::now()
        .checked_add(limits.timeout)
        .context("process timeout is too large")?;
    let mut poll = Duration::from_millis(1);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            terminate(&mut child);
            // The group is gone, so the pipes close and these finish;
            // the grace deadline is only so a descendant that escaped
            // the group cannot turn a timeout into a hang.
            let grace = Instant::now() + GRACE;
            if let Some(writer) = stdin_writer.take() {
                let _ = finish_by(writer, grace);
            }
            let _ = finish_by(stdout_reader, grace);
            let _ = finish_by(stderr_reader, grace);
            bail!("{program} timed out after {:?}", limits.timeout);
        }
        std::thread::sleep(poll);
        poll = (poll * 2).min(Duration::from_millis(20));
    };

    // The direct child has been reaped, but a descendant that inherited
    // the pipes can still hold them open — an unbounded join here would
    // defeat the deadline the caller asked for. The reaped PID (and its
    // process group) may already have been recycled, so the only safe
    // exit is to stop waiting: the readers hold their own pipe ends and
    // retire when the last writer finally closes.
    if let Some(writer) = stdin_writer {
        finish_by(writer, deadline)
            .with_context(|| format!("{program} stdin writer did not finish"))?
            .map_err(|_| anyhow::anyhow!("{program} stdin writer panicked"))??;
    }
    let (stdout, stdout_truncated) = finish_by(stdout_reader, deadline)
        .with_context(|| format!("{program} exited but its stdout pipe is still held open"))?
        .map_err(|_| anyhow::anyhow!("{program} stdout reader panicked"))??;
    let (stderr, stderr_truncated) = finish_by(stderr_reader, deadline)
        .with_context(|| format!("{program} exited but its stderr pipe is still held open"))?
        .map_err(|_| anyhow::anyhow!("{program} stderr reader panicked"))??;
    Ok(ProcessOutput {
        status,
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
    })
}

pub fn is_available(program: &str, args: &[&str]) -> bool {
    let limits = ProcessLimits {
        timeout: Duration::from_secs(5),
        max_output_bytes_per_stream: 1024 * 1024,
    };
    run(Command::new(program).args(args), limits).is_ok_and(|output| output.status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_reader_drains_but_caps_retained_bytes() {
        let (bytes, truncated) = read_bounded(std::io::Cursor::new(vec![7; 100]), 12).unwrap();
        assert_eq!(bytes, vec![7; 12]);
        assert!(truncated);
    }

    /// The direct child exits at once and leaves a descendant holding
    /// its stdout. Waiting on that drain is exactly the hang the
    /// deadline exists to prevent, so it must return an error instead.
    #[cfg(unix)]
    #[test]
    fn drain_of_a_surviving_descendant_is_bounded() {
        let limits = ProcessLimits {
            timeout: Duration::from_millis(200),
            ..Default::default()
        };
        let started = Instant::now();
        let error = run(
            Command::new("sh").args(["-c", "sleep 30 & echo parent-done"]),
            limits,
        )
        .unwrap_err();
        assert!(error.to_string().contains("still held open"), "{error:#}");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "did not give up"
        );
    }

    #[cfg(unix)]
    #[test]
    fn command_timeout_is_enforced() {
        let limits = ProcessLimits {
            timeout: Duration::from_millis(25),
            ..Default::default()
        };
        let error = run(Command::new("sh").args(["-c", "sleep 10"]), limits).unwrap_err();
        assert!(error.to_string().contains("timed out"));
    }
}
