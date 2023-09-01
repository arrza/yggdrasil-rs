use ed25519_dalek::{PublicKey, Signature, Verifier};
use ironwood_rs::network::crypto::{PublicKeyBytes, SIGNATURE_SIZE};
use ironwood_rs::types::Addr;
use log::debug;
use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::address::{
    self, addr_for_key, get_key, get_key_subnet, subnet_for_key, to_ipv6, Address, Subnet,
};
use crate::core::{Core, CoreRead};
use crate::error::YggErrors;

const KEY_STORE_TIMEOUT: Duration = Duration::from_secs(120);

// Out-of-band packet types
const TYPE_KEY_DUMMY: u8 = 0;
const TYPE_KEY_LOOKUP: u8 = 1;
const TYPE_KEY_RESPONSE: u8 = 2;

type KeyArray = [u8; 32];

#[derive(Clone)]
pub struct KeyInfo {
    key: KeyArray,
    address: Address,
    subnet: Subnet,
    timeout: Instant,
}

#[derive(Clone, PartialEq)]
struct Buffer {
    packet: Vec<u8>,
    timeout: Instant,
}

struct KeyStoreTables {
    pub key_to_info: HashMap<KeyArray, KeyInfo>,
    pub addr_to_info: HashMap<Address, KeyInfo>,
    pub subnet_to_info: HashMap<Subnet, KeyInfo>,
}
impl KeyStoreTables {
    pub fn new() -> Self {
        KeyStoreTables {
            key_to_info: HashMap::new(),
            addr_to_info: HashMap::new(),
            subnet_to_info: HashMap::new(),
        }
    }

    pub fn check_timeout(&mut self, key: &KeyArray) {
        if let Some(nfo) = self.key_to_info.get(key) {
            if nfo.timeout <= Instant::now() {
                return;
            }
        }
        if let Some(nfo) = self.key_to_info.remove(key) {
            self.addr_to_info.remove(&nfo.address);
            self.subnet_to_info.remove(&nfo.subnet);
        }
    }
}

fn reset_timeout(info: &mut KeyInfo) {
    info.timeout = Instant::now() + KEY_STORE_TIMEOUT;
}

#[derive(Clone)]
pub struct KeyStore {
    pub core: Arc<Core>,
    address: Address,
    subnet: Subnet,
    tables: Arc<Mutex<KeyStoreTables>>,
    addr_buffer: Arc<Mutex<HashMap<Address, Buffer>>>,
    subnet_buffer: Arc<Mutex<HashMap<Subnet, Buffer>>>,
    mtu: u64,
}

pub struct KeyStoreRead {
    pub core: Arc<Core>,
    pub core_read: CoreRead,
    address: Address,
    subnet: Subnet,
    tables: Arc<Mutex<KeyStoreTables>>,
    addr_buffer: Arc<Mutex<HashMap<Address, Buffer>>>,
    subnet_buffer: Arc<Mutex<HashMap<Subnet, Buffer>>>,
    mtu: u64,
}

impl KeyStore {
    pub fn new(core: Arc<Core>, core_read: CoreRead) -> (Self, KeyStoreRead) {
        //core.pconn.pconn.set_out_of_band_handler();
        let tables = Arc::new(Mutex::new(KeyStoreTables::new()));
        let addr_buffer = Arc::new(Mutex::new(HashMap::new()));
        let subnet_buffer = Arc::new(Mutex::new(HashMap::new()));
        (
            KeyStore {
                address: addr_for_key(&core.public.into()).unwrap(),
                subnet: subnet_for_key(&core.public.into()).unwrap(),
                tables: tables.clone(),
                addr_buffer: addr_buffer.clone(),
                subnet_buffer: subnet_buffer.clone(),
                mtu: 53000,
                core: core.clone(),
            },
            KeyStoreRead {
                address: addr_for_key(&core.public.into()).unwrap(),
                subnet: subnet_for_key(&core.public.into()).unwrap(),
                tables: tables.clone(),
                addr_buffer: addr_buffer.clone(),
                subnet_buffer: subnet_buffer.clone(),
                mtu: 53000,
                core: core.clone(),
                core_read,
            },
        )
    }
    pub async fn send_to_address(
        &mut self,
        addr: Address,
        bs: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        debug!("++send_to_address");
        let dest = {
            let mut tables = self.tables.lock().unwrap();
            if let Some(info) = tables.addr_to_info.get_mut(&addr) {
                reset_timeout(info);
                Some(Addr(PublicKeyBytes(info.key)))
            } else {
                None
            }
        };

        if let Some(addr) = dest {
            self.core.write_to(bs, addr).await?;
        } else {
            {
                let mut addr_buffer = self.addr_buffer.lock().unwrap();
                let buf = addr_buffer.entry(addr).or_insert(Buffer {
                    packet: Vec::new(),
                    timeout: Instant::now() + KEY_STORE_TIMEOUT,
                });

                buf.packet = bs.to_vec();
                buf.timeout = Instant::now() + KEY_STORE_TIMEOUT;
            }

            self.send_key_lookup(get_key(&addr).to_bytes()).await?;
        }
        debug!("--send_to_address");
        Ok(())
    }

    pub async fn send_to_subnet(
        &mut self,
        subnet: Subnet,
        bs: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        debug!("++send_to_subnet");
        let info = if let Some(info) = self.tables.lock().unwrap().subnet_to_info.get_mut(&subnet) {
            reset_timeout(info);
            Some(info.clone())
        } else {
            None
        };
        if let Some(info) = info {
            self.core
                .write_to(bs, Addr(PublicKeyBytes(info.key)))
                .await?;
        } else {
            {
                let mut subnet_buffer = self.subnet_buffer.lock().unwrap();
                let buf = subnet_buffer.entry(subnet).or_insert(Buffer {
                    packet: Vec::new(),
                    timeout: Instant::now() + KEY_STORE_TIMEOUT,
                });

                buf.packet = bs.to_vec();
                buf.timeout = Instant::now() + KEY_STORE_TIMEOUT;
            }
            //let buf_clone = buf.clone();

            self.send_key_lookup(get_key_subnet(&subnet).to_bytes())
                .await?;
        }
        debug!("--send_to_subnet");
        Ok(())
    }

    pub async fn update(&self, key: PublicKeyBytes) -> KeyInfo {
        let mut k_array = [0u8; 32];
        k_array.copy_from_slice(key.as_bytes());
        let mut packets: Vec<Vec<u8>> = Vec::new();
        let ret_info;
        {
            let mut tables = self.tables.lock().unwrap();
            tables.check_timeout(&k_array);
            let info = if let Some(info) = tables.key_to_info.get_mut(&k_array) {
                info
            } else {
                let addr = addr_for_key(&key).unwrap();
                let subnet = subnet_for_key(&key).unwrap();

                let info = KeyInfo {
                    key: k_array,
                    address: addr,
                    subnet: subnet,
                    timeout: Instant::now() + KEY_STORE_TIMEOUT,
                };

                if let Some(buf) = self.addr_buffer.lock().unwrap().remove(&addr) {
                    packets.push(buf.packet.clone());
                }

                if let Some(buf) = self.subnet_buffer.lock().unwrap().remove(&subnet) {
                    packets.push(buf.packet.clone());
                }
                tables.key_to_info.insert(k_array, info.clone());
                tables.addr_to_info.insert(addr, info.clone());
                tables.subnet_to_info.insert(subnet, info.clone());
                tables.key_to_info.get_mut(&k_array).unwrap()
            };

            reset_timeout(info);
            ret_info = info.clone();
        }

        for packet in packets {
            let _ = self
                .core
                .write_to(&packet, Addr(PublicKeyBytes(ret_info.key)))
                .await;
        }

        ret_info
    }

    pub async fn oob_handler(&self, from_key: PublicKeyBytes, to_key: PublicKeyBytes, data: &[u8]) {
        if data.len() != 1 + SIGNATURE_SIZE {
            return;
        }
        let pub_key: PublicKey = from_key.clone().into();
        let sig = Signature::from_bytes(&data[1..]).unwrap();
        match data[0] {
            TYPE_KEY_LOOKUP => {
                let snet = subnet_for_key(&to_key).unwrap();
                if snet == self.subnet && pub_key.verify(to_key.as_bytes(), &sig).is_ok() {
                    self.send_key_response(from_key.to_bytes()).await;
                }
            }
            TYPE_KEY_RESPONSE => {
                if pub_key.verify(to_key.as_bytes(), &sig).is_ok() {
                    self.update(from_key).await;
                }
            }
            _ => {}
        }
    }

    async fn send_key_lookup(&self, partial: KeyArray) -> Result<(), Box<dyn Error>> {
        let sig = self.core.pconn.pconn.private_key().sign(&partial);
        let mut bs: Vec<u8> = vec![TYPE_KEY_LOOKUP];
        bs.extend_from_slice(sig.as_bytes());
        self.core
            .pconn
            .pconn
            .send_out_of_band(PublicKeyBytes(partial), bs)
            .await
    }

    async fn send_key_response(&self, dest: KeyArray) -> Result<(), Box<dyn Error>> {
        let sig = self.core.pconn.pconn.private_key().sign(&dest);
        let mut bs: Vec<u8> = vec![TYPE_KEY_RESPONSE];
        bs.extend_from_slice(sig.as_bytes());
        self.core
            .pconn
            .pconn
            .send_out_of_band(PublicKeyBytes(dest), bs)
            .await
    }

    // Here is the conversion for writePC
    pub async fn write_pc(&mut self, bs: &[u8]) -> Result<usize, YggErrors> {
        if bs[0] & 0xf0 != 0x60 {
            return Err(YggErrors::InvalidPacket); // not IPv6
        }

        if bs.len() < 40 {
            return Err(YggErrors::UnderSizedIpv6Packet(bs.len()));
        }

        let mut src_addr: Address = [0; 16];
        src_addr.copy_from_slice(&bs[8..24]);
        let mut dst_addr: Address = [0; 16];
        dst_addr.copy_from_slice(&bs[24..40]);
        let src_subnet: Subnet = bs[8..16].try_into().unwrap();
        let dst_subnet: Subnet = bs[24..32].try_into().unwrap();

        if src_addr != self.address && src_subnet != self.subnet {
            return Err(YggErrors::InvalidSourceAddress(
                to_ipv6(&self.address),
                to_ipv6(&src_addr),
            ));
        }

        if address::is_valid(&dst_addr) {
            self.send_to_address(dst_addr, bs)
                .await
                .map_err(|e| YggErrors::SendError(e.to_string()))?;
        } else if address::is_valid_subnet(&dst_subnet) {
            self.send_to_subnet(dst_subnet, bs)
                .await
                .map_err(|e| YggErrors::SendError(e.to_string()))?;
        } else {
            return Err(YggErrors::InvalidDestinationAddress(to_ipv6(&dst_addr)));
        }

        Ok(bs.len())
    }
}

impl KeyStoreRead {
    pub async fn update(&mut self, key: PublicKeyBytes) -> KeyInfo {
        let mut packets: Vec<Vec<u8>> = Vec::new();

        let mut k_array = [0u8; 32];
        k_array.copy_from_slice(key.as_bytes());
        let info_cln;
        {
            let mut tables = self.tables.lock().unwrap();
            tables.check_timeout(&k_array);

            let info = if let Some(info) = tables.key_to_info.get_mut(&k_array) {
                info
            } else {
                let addr = addr_for_key(&key).unwrap();
                let subnet = subnet_for_key(&key).unwrap();

                let info = KeyInfo {
                    key: k_array,
                    address: addr,
                    subnet,
                    timeout: Instant::now() + KEY_STORE_TIMEOUT,
                };

                if let Some(buf) = self.addr_buffer.lock().unwrap().remove(&addr) {
                    packets.push(buf.packet.clone());
                }

                if let Some(buf) = self.subnet_buffer.lock().unwrap().remove(&subnet) {
                    packets.push(buf.packet.clone());
                }
                tables.key_to_info.insert(k_array, info.clone());
                tables.addr_to_info.insert(addr, info.clone());
                tables.subnet_to_info.insert(subnet, info.clone());
                tables.key_to_info.get_mut(&k_array).unwrap()
            };
            reset_timeout(info);
            info_cln = info.clone();
        }

        for packet in packets {
            let _ = self
                .core
                .write_to(&packet, Addr(PublicKeyBytes(info_cln.key)))
                .await;
        }

        info_cln
    }

    pub async fn read_pc(&mut self, buf: &mut [u8]) -> Result<usize, String> {
        debug!("++read_pc");
        //let mut buf = vec![0u8; 65536];
        debug!("  read_pc.1");
        loop {
            let (n, from) = self.core_read.read_from(buf).await?;
            debug!("Read pkt: {} {}", n, from);
            if n == 0 {
                continue;
            }

            let bs = &buf[..n];

            if bs[0] & 0xf0 != 0x60 {
                continue; // not IPv6
            }

            debug!("  read_pc.2");

            if bs.len() < 40 {
                continue;
            }

            debug!("  read_pc.3");
            let mtu = self.mtu;

            if bs.len() > mtu as usize {
                // Handle oversized packets...
                continue;
            }

            debug!("  read_pc.4");
            let mut src_addr: Address = [0; 16];
            src_addr.copy_from_slice(&bs[8..24]);
            let mut dst_addr: Address = [0; 16];
            dst_addr.copy_from_slice(&bs[24..40]);
            let src_subnet: Subnet = bs[8..16].try_into().unwrap();
            let dst_subnet: Subnet = bs[24..32].try_into().unwrap();

            debug!("  read_pc.5");
            if dst_addr != self.address && dst_subnet != self.subnet {
                continue; // bad local address/subnet
            }

            let info = self.update(from.0).await;

            debug!("  read_pc.6");
            if src_addr != info.address && src_subnet != info.subnet {
                continue; // bad remote address/subnet
            }

            let n = bs.len().min(buf.len());
            //buf[..n].copy_from_slice(&bs[..n]);
            debug!("--read_pc: {}", n);
            return Ok(n);
        }
        debug!("--read_pc");
    }
}

pub struct ReadWriteCloser {
    pub key_store: KeyStore,
}

pub struct ReadWriteCloserRead {
    key_store: KeyStoreRead,
}

impl ReadWriteCloser {
    pub fn new(core: Arc<Core>, core_read: CoreRead) -> (Self, ReadWriteCloserRead) {
        let (key_store, key_store_read) = KeyStore::new(core, core_read);
        (
            ReadWriteCloser { key_store },
            ReadWriteCloserRead {
                key_store: key_store_read,
            },
        )
    }

    pub fn address(&self) -> Address {
        self.key_store.address
    }

    pub fn subnet(&self) -> Subnet {
        self.key_store.subnet
    }

    pub fn max_mtu(&self) -> u16 {
        self.key_store.core.mtu() as u16
    }

    pub fn set_mtu(&mut self, mtu: u16) {
        self.key_store.mtu = mtu.into();
    }

    pub async fn write(&mut self, bs: &[u8]) -> Result<usize, YggErrors> {
        self.key_store.write_pc(bs).await
    }
}

impl ReadWriteCloserRead {
    pub fn address(&self) -> Address {
        self.key_store.address
    }

    pub fn subnet(&self) -> Subnet {
        self.key_store.subnet
    }

    pub async fn read(&mut self, bs: &mut [u8]) -> Result<usize, String> {
        self.key_store.read_pc(bs).await
    }

    pub fn set_mtu(&mut self, mtu: u16) {
        self.key_store.mtu = mtu.into();
    }
}
