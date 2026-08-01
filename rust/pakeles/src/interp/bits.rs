//! Bit-granular big-endian reads. This is the *reference* implementation:
//! clarity wins over speed, deliberately bit-by-bit.

/// Read `n` bits (1..=64) starting at absolute bit offset `bit_off`,
/// MSB-first within each byte, big-endian across bytes. `None` if the
/// read would run past `avail_bits` (the input's bit-granular length).
pub(crate) fn read_bits(bytes: &[u8], avail_bits: usize, bit_off: usize, n: usize) -> Option<u64> {
    debug_assert!((1..=64).contains(&n));
    debug_assert!(avail_bits <= bytes.len() * 8);
    if bit_off.checked_add(n)? > avail_bits {
        return None;
    }
    let mut out = 0u64;
    for i in 0..n {
        let pos = bit_off + i;
        let bit = (bytes[pos / 8] >> (7 - pos % 8)) & 1;
        out = (out << 1) | u64::from(bit);
    }
    Some(out)
}

/// Copy `n` bits starting at absolute bit offset `bit_off` into a fresh
/// canonical byte vector: MSB-first, `ceil(n/8)` bytes, unused trailing
/// low-order bits zero (the BitString contract). The caller has already
/// bounds-checked `bit_off + n`; like `read_bits`, deliberately
/// bit-by-bit — reference clarity over speed.
pub(crate) fn read_run(bytes: &[u8], bit_off: usize, n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n.div_ceil(8)];
    for i in 0..n {
        let pos = bit_off + i;
        let bit = (bytes[pos / 8] >> (7 - pos % 8)) & 1;
        out[i / 8] |= bit << (7 - i % 8);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::read_bits;
    use super::read_run;

    #[test]
    fn reads_msb_first() {
        let b = [0xAB, 0xCD];
        assert_eq!(read_bits(&b, 16, 0, 4).unwrap(), 0xA);
        assert_eq!(read_bits(&b, 16, 4, 8).unwrap(), 0xBC);
        assert_eq!(read_bits(&b, 16, 0, 16).unwrap(), 0xABCD);
        assert_eq!(read_bits(&b, 16, 15, 1).unwrap(), 0x1);
    }

    #[test]
    fn oob_is_none() {
        assert!(read_bits(&[0xFF], 8, 4, 8).is_none());
        assert!(read_bits(&[], 0, 0, 1).is_none());
    }

    #[test]
    fn bit_granular_limit_respected() {
        let b = [0xFF, 0xFF];
        assert_eq!(read_bits(&b, 12, 8, 4).unwrap(), 0xF);
        assert!(read_bits(&b, 12, 8, 5).is_none());
    }

    #[test]
    fn run_copies_aligned_bytes() {
        let b = [0xAB, 0xCD, 0xEF];
        assert_eq!(read_run(&b, 8, 16), vec![0xCD, 0xEF]);
    }

    #[test]
    fn run_shifts_misaligned_and_zero_pads() {
        let b = [0xAB, 0xCD];
        // 12 bits from offset 4: 0xBCD -> bytes [0xBC, 0xD0].
        assert_eq!(read_run(&b, 4, 12), vec![0xBC, 0xD0]);
        // 5 bits from offset 0: 0b10101 -> [0xA8].
        assert_eq!(read_run(&b, 0, 5), vec![0xA8]);
    }
}
