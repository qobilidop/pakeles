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
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            terminate(&mut child);
            if let Some(writer) = stdin_writer.take() {
                let _ = writer.join();
            }
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            bail!("{program} timed out after {:?}", limits.timeout);
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    if let Some(writer) = stdin_writer {
        writer
            .join()
            .map_err(|_| anyhow::anyhow!("{program} stdin writer panicked"))??;
    }
    let (stdout, stdout_truncated) = stdout_reader
        .join()
        .map_err(|_| anyhow::anyhow!("{program} stdout reader panicked"))??;
    let (stderr, stderr_truncated) = stderr_reader
        .join()
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
