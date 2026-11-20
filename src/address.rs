//! Yggdrasil IPv6 address derivation from ed25519 public keys.
//!
//! Addresses use the `200::/7` range:
//! - `200::/8` for individual node `/128` addresses (prefix 0x02)
//! - `300::/8` for optional `/64` subnet prefixes (prefix 0x03)
//!
//! Adapted from yggdrasil/src/address.rs for no_std.

use core::fmt;

const ADDRESS_PREFIX: u8 = 0x02;
const SUBNET_PREFIX: u8 = 0x03;

/// Yggdrasil IPv6 address (16 bytes, prefix 0x02).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Address(pub [u8; 16]);

/// Yggdrasil /64 subnet (8 bytes, prefix 0x03).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Subnet(pub [u8; 8]);

impl Address {
    /// Check if this is a valid Yggdrasil address (starts with 0x02).
    pub fn is_valid(&self) -> bool {
        self.0[0] == ADDRESS_PREFIX
    }

    /// Reconstruct a partial ed25519 public key from this address.
    /// Used for DHT/bloom lookups; same result as Go's GetKey(), byte-wise (it runs per
    /// packet through the bloom transform).
    pub fn get_key(&self) -> [u8; 32] {
        let ones = self.0[1] as usize;
        let mut key = [0u8; 32];
        // `ones` leading one bits (then the zero bit is left as is).
        let full = (ones / 8).min(32);
        for b in key.iter_mut().take(full) {
            *b = 0xff;
        }
        if full < 32 && ones % 8 != 0 {
            key[full] = !(0xffu8 >> (ones % 8));
        }
        // The 14 address bytes after the zero bit.
        let offset = ones + 1;
        for i in 0..14 {
            let b = self.0[2 + i];
            let p = offset + 8 * i;
            let (q, r) = (p / 8, p % 8);
            if q >= 32 {
                break;
            }
            key[q] |= b >> r;
            if r != 0 && q + 1 < 32 {
                key[q + 1] |= b << (8 - r);
            }
        }
        for byte in &mut key {
            *byte = !*byte;
        }
        key
    }
}

impl Subnet {
    /// Check if this is a valid Yggdrasil subnet (starts with 0x03).
    pub fn is_valid(&self) -> bool {
        self.0[0] == SUBNET_PREFIX
    }

    /// Reconstruct a partial ed25519 public key from this subnet.
    pub fn get_key(&self) -> [u8; 32] {
        let mut addr_bytes = [0u8; 16];
        addr_bytes[..8].copy_from_slice(&self.0);
        addr_bytes[0] &= !0x01;
        let addr = Address(addr_bytes);
        addr.get_key()
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let a = &self.0;
        write!(
            f,
            "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            u16::from_be_bytes([a[0], a[1]]),
            u16::from_be_bytes([a[2], a[3]]),
            u16::from_be_bytes([a[4], a[5]]),
            u16::from_be_bytes([a[6], a[7]]),
            u16::from_be_bytes([a[8], a[9]]),
            u16::from_be_bytes([a[10], a[11]]),
            u16::from_be_bytes([a[12], a[13]]),
            u16::from_be_bytes([a[14], a[15]]),
        )
    }
}

impl fmt::Display for Subnet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = &self.0;
        write!(
            f,
            "{:x}:{:x}:{:x}:{:x}::/64",
            u16::from_be_bytes([s[0], s[1]]),
            u16::from_be_bytes([s[2], s[3]]),
            u16::from_be_bytes([s[4], s[5]]),
            u16::from_be_bytes([s[6], s[7]]),
        )
    }
}

/// Derive a Yggdrasil IPv6 address from an ed25519 public key.
/// Same result as Go's `AddrForKey`: on the inverted key, the number of leading one bits,
/// then the bits after the first zero, packed into whole bytes (up to 14). Byte-wise and
/// without allocating: it runs for every packet, and the bit-by-bit loop with a `Vec` was
/// a fifth of an exit's CPU time.
pub fn addr_for_key(public_key: &[u8; 32]) -> Address {
    let mut buf = *public_key;
    for byte in &mut buf {
        *byte = !*byte;
    }
    let mut ones: usize = 0;
    for &b in &buf {
        let n = b.leading_ones() as usize;
        ones += n;
        if n < 8 {
            break;
        }
    }
    let mut addr = [0u8; 16];
    addr[0] = ADDRESS_PREFIX;
    addr[1] = ones.min(255) as u8;
    // Bits after the first zero (none if the inverted key is all ones).
    let start = ones + 1;
    if start <= 256 {
        let full = ((256 - start) / 8).min(14);
        for i in 0..full {
            let p = start + 8 * i;
            let (q, r) = (p / 8, p % 8);
            addr[2 + i] = if r == 0 { buf[q] } else { (buf[q] << r) | (buf[q + 1] >> (8 - r)) };
        }
    }
    Address(addr)
}

/// Derive a Yggdrasil /64 subnet from an ed25519 public key.
/// Exact port of Go's `SubnetForKey`.
pub fn subnet_for_key(public_key: &[u8; 32]) -> Subnet {
    let addr = addr_for_key(public_key);
    let mut subnet = [0u8; 8];
    subnet.copy_from_slice(&addr.0[..8]);
    subnet[0] |= 0x01;
    Subnet(subnet)
}

/// Check if an IPv6 address (16 bytes) is a valid Yggdrasil address.
pub fn is_valid_address(addr: &[u8; 16]) -> bool {
    addr[0] == ADDRESS_PREFIX
}

/// Check if an IPv6 /64 prefix (first 8 bytes) is a valid Yggdrasil subnet.
pub fn is_valid_subnet(prefix: &[u8; 8]) -> bool {
    prefix[0] == SUBNET_PREFIX
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The original bit-by-bit port of Go's `AddrForKey`, as the reference.
    fn addr_for_key_reference(public_key: &[u8; 32]) -> [u8; 16] {
        let mut buf = *public_key;
        for byte in &mut buf {
            *byte = !*byte;
        }
        let (mut ones, mut done, mut temp, mut bits, mut n_bits) = (0usize, false, alloc::vec::Vec::new(), 0u8, 0u8);
        for idx in 0..(8 * 32) {
            let bit = (buf[idx / 8] & (0x80 >> (idx % 8))) >> (7 - (idx % 8));
            if !done && bit != 0 {
                ones += 1;
                continue;
            }
            if !done && bit == 0 {
                done = true;
                continue;
            }
            bits = (bits << 1) | bit;
            n_bits += 1;
            if n_bits == 8 {
                temp.push(bits);
                bits = 0;
                n_bits = 0;
            }
        }
        let mut addr = [0u8; 16];
        addr[0] = ADDRESS_PREFIX;
        addr[1] = ones.min(255) as u8;
        let n = temp.len().min(14);
        addr[2..2 + n].copy_from_slice(&temp[..n]);
        addr
    }

    /// The original bit-by-bit port of Go's `GetKey`, as the reference.
    fn get_key_reference(a: &[u8; 16]) -> [u8; 32] {
        let ones = a[1] as usize;
        let mut key = [0u8; 32];
        for idx in 0..ones {
            if idx / 8 >= 32 {
                break;
            }
            key[idx / 8] |= 0x80 >> (idx % 8);
        }
        let key_offset = ones + 1;
        for idx in 0..(8 * 14) {
            let bit = (a[2 + idx / 8] >> (7 - (idx % 8))) & 1;
            let pos = key_offset + idx;
            if pos / 8 >= 32 {
                break;
            }
            key[pos / 8] |= bit << (7 - (pos % 8));
        }
        for b in &mut key {
            *b = !*b;
        }
        key
    }

    #[test]
    fn get_key_matches_the_reference() {
        let mut x: u64 = 0x2545_f491_4f6c_dd1d;
        for ones in 0..=255u8 {
            for _ in 0..8 {
                let mut a = [0u8; 16];
                a[0] = 0x02;
                a[1] = ones;
                for b in a.iter_mut().skip(2) {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    *b = x as u8;
                }
                assert_eq!(Address(a).get_key(), get_key_reference(&a), "addr {a:02x?}");
            }
        }
    }

    #[test]
    fn addr_for_key_matches_the_reference() {
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut keys: alloc::vec::Vec<[u8; 32]> = alloc::vec![[0u8; 32], [0xff; 32]];
        for lead in 0..40 {
            // Keys with `lead` leading zero bits (= leading ones after inversion).
            let mut k = [0xa5u8; 32];
            for i in 0..lead {
                k[i / 8] &= !(0x80 >> (i % 8));
            }
            if lead < 256 {
                k[lead / 8] |= 0x80 >> (lead % 8);
            }
            keys.push(k);
        }
        for _ in 0..2000 {
            let mut k = [0u8; 32];
            for b in &mut k {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                *b = x as u8;
            }
            // Some with long zero prefixes (vanity keys).
            let z = (x % 7) as usize;
            for b in k.iter_mut().take(z) {
                *b = 0;
            }
            keys.push(k);
        }
        for k in &keys {
            assert_eq!(addr_for_key(k).0, addr_for_key_reference(k), "key {k:02x?}");
        }
    }

    #[test]
    fn test_addr_for_key_basic() {
        let key = [0u8; 32];
        let addr = addr_for_key(&key);
        assert_eq!(addr.0[0], 0x02);
        assert!(addr.is_valid());
    }

    #[test]
    fn test_subnet_for_key_basic() {
        let key = [0u8; 32];
        let subnet = subnet_for_key(&key);
        assert!(subnet.is_valid());
        assert_eq!(subnet.0[0] & 0x01, 0x01);
    }

    #[test]
    fn test_all_zeros_key() {
        let key = [0u8; 32];
        let addr = addr_for_key(&key);
        assert_eq!(addr.0[0], 0x02);
        assert_eq!(addr.0[1], 255);
    }

    #[test]
    fn test_all_ones_key() {
        let key = [0xFFu8; 32];
        let addr = addr_for_key(&key);
        assert_eq!(addr.0[0], 0x02);
        assert_eq!(addr.0[1], 0);
    }

    #[test]
    fn test_known_key() {
        let mut key = [0u8; 32];
        key[1] = 0x01;
        key[2] = 0xFF;
        let addr = addr_for_key(&key);
        assert_eq!(addr.0[0], 0x02);
        assert_eq!(addr.0[1], 15);
    }

    #[test]
    fn test_get_key_roundtrip() {
        for seed in 0u8..20 {
            let mut key = [0u8; 32];
            key[0] = seed;
            key[31] = seed.wrapping_mul(7);
            let addr = addr_for_key(&key);
            let recovered = addr.get_key();
            let addr2 = addr_for_key(&recovered);
            assert_eq!(addr, addr2, "roundtrip failed for seed {}", seed);
        }
    }

    #[test]
    fn test_address_display() {
        let addr = Address([
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ]);
        let s = alloc::format!("{}", addr);
        assert!(s.starts_with("200:"));
    }
}
