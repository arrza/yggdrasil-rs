use ironwood_rs::network::crypto::PublicKeyBytes;
use std::time::Duration;

pub struct SelfInfo {
    pub key: PublicKeyBytes,
    pub root: PublicKeyBytes,
    pub coords: Vec<u64>,
}

pub struct PeerInfo {
    pub key: PublicKeyBytes,
    pub root: PublicKeyBytes,
    pub coords: Vec<u64>,
    pub port: u16,
    pub priority: u8,
    pub remote: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub uptime: Duration,
}
