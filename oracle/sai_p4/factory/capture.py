"""Run the corpus through the instrumented SONiC PINS parser on
simple_switch and emit the (bitmap, err) golden.

Each output frame is exactly the pk_verdict header: 2 bytes big-endian
bitmap + 1 byte parser-error code. simple_switch buffers output under
--use-files, so we pad the input with trailing dummies to flush the real
tail (the bmv2.rs trick), and wait on output-count progress.

Usage: capture.py <sai.json> <corpus.txt> <sonic_pins_commit>
"""

import json
import struct
import subprocess
import sys
import time
from pathlib import Path

FLUSH_PAD = 8


def read_corpus(path: str) -> list[bytes]:
    out = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.append(bytes.fromhex(line))
    return out


def write_pcap(path: Path, pkts: list[bytes]) -> None:
    b = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for p in pkts:
        b += struct.pack("<IIII", 0, 0, len(p), len(p)) + p
    path.write_bytes(b)


def read_pcap(path: Path) -> list[bytes]:
    if not path.exists():
        return []
    b = path.read_bytes()
    if len(b) < 24:
        return []
    out, off = [], 24
    while off + 16 <= len(b):
        _, _, caplen, _ = struct.unpack_from("<IIII", b, off)
        off += 16
        if off + caplen > len(b):
            break
        out.append(b[off : off + caplen])
        off += caplen
    return out


def main() -> None:
    sai_json, corpus_path, commit = sys.argv[1], sys.argv[2], sys.argv[3]
    pkts = read_corpus(corpus_path)
    n = len(pkts)

    run = Path("build/run")
    if run.exists():
        import shutil

        shutil.rmtree(run)
    run.mkdir(parents=True)

    padded = pkts + [pkts[-1]] * FLUSH_PAD
    write_pcap(run / "p0_in.pcap", padded)
    write_pcap(run / "p1_in.pcap", [])

    proc = subprocess.Popen(
        ["simple_switch", "--use-files", "0", "-i", "0@p0", "-i", "1@p1", str(Path(sai_json).resolve())],
        cwd=run,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    out_pcap = run / "p1_out.pcap"
    deadline = time.monotonic() + 120
    seen = 0
    last = time.monotonic()
    frames: list[bytes] = []
    try:
        while True:
            frames = read_pcap(out_pcap)
            if len(frames) > seen:
                seen = len(frames)
                last = time.monotonic()
            if len(frames) >= n:
                break
            if time.monotonic() > deadline or time.monotonic() - last > 30:
                break
            time.sleep(0.2)
    finally:
        proc.kill()

    if len(frames) < n:
        print(f"ERROR: only {len(frames)}/{n} verdict frames", file=sys.stderr)
        sys.exit(1)

    entries = []
    for pkt, frame in zip(pkts, frames[:n]):
        if len(frame) < 3:
            print(f"ERROR: short verdict frame {len(frame)}B", file=sys.stderr)
            sys.exit(1)
        bitmap = (frame[0] << 8) | frame[1]
        err = frame[2]
        entries.append(
            {"packet_hex": pkt.hex(), "bitmap": bitmap, "err": err}
        )

    golden = {"sonic_pins_commit": commit, "entries": entries}
    print(json.dumps(golden, indent=1))


if __name__ == "__main__":
    main()
