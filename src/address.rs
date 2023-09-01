//! Package address contains the types used by yggdrasil to represent IPv6 addresses or prefixes, as well as functions for working with these types.
//! Of particular importance are the functions used to derive addresses or subnets from a NodeID, or to get the NodeID and bitmask of the bits visible from an address, which is needed for DHT searches.

use ironwood_rs::network::crypto::PublicKeyBytes;
use lazy_static::lazy_static;
use std::{collections::HashMap, net::Ipv6Addr, sync::Mutex};

/// Address represents an IPv6 address in the yggdrasil address range.
pub type Address = [u8; 16];

/// Subnet represents an IPv6 /64 subnet in the yggdrasil subnet range.
pub type Subnet = [u8; 8];

/// GetPrefix returns the address prefix used by yggdrasil.
/// The current implementation requires this to be a multiple of 8 bits + 7 bits.
/// The 8th bit of the last byte is used to signal nodes (0) or /64 prefixes (1).
/// Nodes that configure this differently will be unable to communicate with each other using IP packets, though routing and the DHT machinery *should* still work.
pub fn get_prefix() -> [u8; 1] {
    [0x02]
}

pub fn to_ipv6(addr: &Address) -> Ipv6Addr {
    Ipv6Addr::new(
        u16::from_be_bytes([addr[0], addr[1]]),
        u16::from_be_bytes([addr[2], addr[3]]),
        u16::from_be_bytes([addr[4], addr[5]]),
        u16::from_be_bytes([addr[6], addr[7]]),
        u16::from_be_bytes([addr[8], addr[9]]),
        u16::from_be_bytes([addr[10], addr[11]]),
        u16::from_be_bytes([addr[12], addr[13]]),
        u16::from_be_bytes([addr[14], addr[15]]),
    )
}

/// IsValid returns true if an address falls within the range used by nodes in the network.
pub fn is_valid(a: &Address) -> bool {
    let prefix = get_prefix();
    for idx in 0..prefix.len() {
        if a[idx] != prefix[idx] {
            return false;
        }
    }
    true
}

/// IsValid returns true if a prefix falls within the range usable by the network.
pub fn is_valid_subnet(s: &Subnet) -> bool {
    let prefix = get_prefix();
    let l = prefix.len();
    for idx in 0..l - 1 {
        if s[idx] != prefix[idx] {
            return false;
        }
    }
    s[l - 1] == prefix[l - 1] | 0x01
}
lazy_static! {
    static ref ADDR_TABLE: Mutex<HashMap<PublicKeyBytes, Address>> = Mutex::new(HashMap::new());
}
/// AddrForKey takes an ed25519.PublicKey as an argument and returns an *Address.
/// This function returns nil if the key length is not ed25519.PublicKeySize.
/// This address begins with the contents of GetPrefix(), with the last bit set to 0 to indicate an address.
/// The following 8 bits are set to the number of leading 1 bits in the bitwise inverse of the public key.
/// The bitwise inverse of the key, excluding the leading 1 bits and the first leading 0 bit, is truncated to the appropriate length and makes up the remainder of the address.
pub fn addr_for_key(public_key: &PublicKeyBytes) -> Option<Address> {
    // 128 bit address
    // Begins with prefix
    // Next bit is a 0
    // Next 7 bits, interpreted as a uint, are # of leading 1s in the NodeID
    // Leading 1s and first leading 0 of the NodeID are truncated off
    // The rest is appended to the IPv6 address (truncated to 128 bits total)
    if public_key.as_bytes().len() != ed25519_dalek::PUBLIC_KEY_LENGTH {
        return None;
    }
    if let Some(addr) = { ADDR_TABLE.lock().unwrap().get(public_key).cloned() } {
        return Some(addr);
    }
    let mut buf: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] = [0; ed25519_dalek::PUBLIC_KEY_LENGTH];
    buf.copy_from_slice(public_key.as_bytes());
    (0..buf.len()).for_each(|idx| {
        buf[idx] = !buf[idx];
    });
    let mut addr: Address = [0; 16];
    let mut temp = Vec::with_capacity(256);
    let mut done = false;
    let mut ones = 0u8;
    let mut bits = 0u8;
    let mut n_bits = 0u8;
    for idx in 0..8 * buf.len() {
        let bit = (buf[idx / 8] & (0x80 >> (idx % 8) as u8)) >> (7 - (idx % 8)) as u8;
        if !done && bit != 0 {
            ones += 1;
            continue;
        }
        if !done && bit == 0 {
            done = true;
            continue; // FIXME? this assumes that ones <= 127, probably only worth changing by using a variable length uint64, but that would require changes to the addressing scheme, and I'm not sure ones > 127 is realistic
        }
        bits = (bits << 1) | bit;
        n_bits += 1;
        if n_bits == 8 {
            n_bits = 0;
            temp.push(bits);
        }
    }
    let prefix = get_prefix();
    addr[..prefix.len()].copy_from_slice(&prefix);
    addr[prefix.len()] = ones;
    addr[prefix.len() + 1..].copy_from_slice(&temp[..16 - prefix.len() - 1]);
    ADDR_TABLE.lock().unwrap().insert(public_key.clone(), addr);
    Some(addr)
}

/// SubnetForKey takes an ed25519.PublicKey as an argument and returns a *Subnet.
/// This function returns nil if the key length is not ed25519.PublicKeySize.
/// The subnet begins with the address prefix, with the last bit set to 1 to indicate a prefix.
/// The following 8 bits are set to the number of leading 1 bits in the bitwise inverse of the key.
/// The bitwise inverse of the key, excluding the leading 1 bits and the first leading 0 bit, is truncated to the appropriate length and makes up the remainder of the subnet.
pub fn subnet_for_key(public_key: &PublicKeyBytes) -> Option<Subnet> {
    // Exactly as the address version, with two exceptions:
    //  1) The first bit after the fixed prefix is a 1 instead of a 0
    //  2) It's truncated to a subnet prefix length instead of 128 bits
    let addr = addr_for_key(public_key)?;
    let mut snet: Subnet = [0; 8];
    snet.copy_from_slice(&addr[..8]);
    let prefix = get_prefix(); // nolint:staticcheck
    snet[prefix.len() - 1] |= 0x01;
    Some(snet)
}

/// GetKet returns the partial ed25519.PublicKey for the Address.
/// This is used for key lookup.
pub fn get_key(a: &Address) -> PublicKeyBytes {
    let mut key: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] = [0; ed25519_dalek::PUBLIC_KEY_LENGTH];
    let prefix = get_prefix(); // nolint:staticcheck
    let ones = a[prefix.len()] as usize;
    for idx in 0..ones {
        key[idx / 8] |= 0x80 >> (idx % 8) as u8;
    }
    let key_offset = ones + 1;
    let addr_offset = 8 * prefix.len() + 8;
    for idx in addr_offset..8 * a.len() {
        let bits = a[idx / 8] & (0x80 >> (idx % 8) as u8);
        let bits = bits << (idx % 8) as u8;
        let key_idx = key_offset + (idx - addr_offset);
        let bits = bits >> (key_idx % 8) as u8;
        let idx = key_idx / 8;
        if idx >= key.len() {
            break;
        }
        key[idx] |= bits;
    }
    (0..key.len()).for_each(|idx| {
        key[idx] = !key[idx];
    });
    PublicKeyBytes(key)
}

/// GetKet returns the partial ed25519.PublicKey for the Subnet.
/// This is used for key lookup.
pub fn get_key_subnet(s: &Subnet) -> PublicKeyBytes {
    let mut addr: Address = Address::default();
    addr[..8].copy_from_slice(&s[..]);
    get_key(&addr)
}
