use crate::{
    address::{addr_for_key, address_to_ipv6},
    version::VersionMetadata,
    Core,
};
use ironwood_rs::network::{
    crypto::PublicKeyBytes,
    wire::{Decode, Encode},
};
use log::{debug, info};
use std::{
    collections::HashMap,
    error::Error,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, MutexGuard,
    },
    time::Instant,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use url::Url;

use super::link_tcp::LinkTCP;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LinkInfo {
    link_type: String,
    local: String,
    remote: String,
}

pub struct LinkDial {
    pub url: Url,
    pub sintf: String,
}

#[derive(Clone)]
pub struct LinkInternal {
    lname: String,
    conn: LinkConnHandle,
    options: LinkOptions,
    info: LinkInfo,
    incoming: bool,
    force: bool,
}
#[derive(Clone)]
pub struct Link {
    links: Links,
    inner: Arc<Mutex<LinkInternal>>,
}

#[derive(Clone)]
pub struct LinkOptions {
    pinned_ed25519_keys: HashMap<PublicKeyBytes, ()>,
    priority: u8,
}

#[derive(Clone)]
pub struct Links {
    pub links: Arc<Mutex<HashMap<LinkInfo, Link>>>,
}

pub fn link_info_for(link_type: &str, sintf: &str, remote: &str) -> LinkInfo {
    LinkInfo {
        link_type: link_type.to_string(),
        local: sintf.to_string(),
        remote: remote.to_string(),
    }
}

pub struct LinkConn {
    rx: Arc<AtomicU64>,
    tx: Arc<AtomicU64>,
    up: Arc<Instant>,
    pub conn: TcpStream,
}

#[derive(Clone)]
pub struct LinkConnHandle {
    pub rx: Arc<AtomicU64>,
    pub tx: Arc<AtomicU64>,
    pub up: Arc<Instant>,
    pub remote_addr: String,
}

impl LinkConn {
    fn new(conn: TcpStream) -> Self {
        LinkConn {
            rx: Arc::new(AtomicU64::new(0)),
            tx: Arc::new(AtomicU64::new(0)),
            up: Arc::new(Instant::now()),
            conn,
        }
    }
    fn handle(&self) -> LinkConnHandle {
        LinkConnHandle {
            rx: self.rx.clone(),
            tx: self.tx.clone(),
            up: self.up.clone(),
            remote_addr: self.conn.peer_addr().unwrap().to_string(),
        }
    }

    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let result = self.conn.read(buf).await?;
        self.rx.fetch_add(result as u64, Ordering::Relaxed);
        Ok(result)
    }

    async fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let result = self.conn.read_exact(buf).await?;
        self.rx.fetch_add(result as u64, Ordering::Relaxed);
        Ok(result)
    }

    async fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let result = self.conn.write(buf).await?;
        self.tx.fetch_add(result as u64, Ordering::Relaxed);
        Ok(result)
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        self.conn.flush().await
    }
}

impl Links {
    pub async fn create(
        &self,
        core: Arc<Core>,
        conn: TcpStream,
        dial: LinkDial,
        name: String,
        info: LinkInfo,
        incoming: bool,
        force: bool,
        options: LinkOptions,
    ) -> Result<(), Box<dyn std::error::Error>> {
        debug!("++create");
        let conn = LinkConn::new(conn);
        let mut intf = Link {
            links: self.clone(),
            inner: Arc::new(Mutex::new(LinkInternal {
                conn: conn.handle(),
                lname: name.clone(),
                options,
                info,
                incoming,
                force,
            })),
        };
        debug!("  create.1");
        tokio::spawn(async move {
            let peer_addr = conn.conn.peer_addr().unwrap();
            if let Err(err) = intf.handler(core, conn, dial).await {
                eprintln!("Link handler {} error ({:?}): {}", name, peer_addr, err);
            }
        });
        debug!("--create");
        Ok(())
    }

    pub fn is_connected_to(&self, info: &LinkInfo) -> bool {
        if self.links.lock().unwrap().get(info).is_some() {
            return true;
        }
        false
    }

    pub async fn call(
        &self,
        core: Arc<Core>,
        url: &url::Url,
        sintf: &str,
    ) -> Result<LinkInfo, Box<dyn Error>> {
        let info = LinkInfo {
            link_type: url.scheme().to_string(),
            local: "local_addr".to_string(), // Update this with the actual local address
            remote: url.host_str().unwrap_or("").to_string(),
        };

        if self.is_connected_to(&info) {
            return Ok(info);
        }

        let mut options = LinkOptions {
            pinned_ed25519_keys: HashMap::new(),
            priority: 0,
        };

        for pubkey in url
            .query_pairs()
            .filter(|(key, _)| key == "key")
            .map(|(_, value)| value)
        {
            if let Ok(sig_pub) = hex::decode(pubkey.as_bytes()) {
                let mut sig_pub_key = [0u8; 32]; // Assuming Ed25519 key size
                sig_pub_key.copy_from_slice(&sig_pub);
                options
                    .pinned_ed25519_keys
                    .insert(PublicKeyBytes(sig_pub_key), ());
            } else {
                return Ok(info);
            }
        }

        if let Some(priority) = url
            .query_pairs()
            .find(|(key, _)| key == "priority")
            .map(|(_, value)| value)
        {
            if let Ok(pi) = priority.parse::<u8>() {
                options.priority = pi;
            } else {
                return Ok(info);
            }
        }

        let dial_info = info.clone();
        let tcp_link = LinkTCP {
            links: self.clone(),
        };
        tcp_link.dial(core, url, options, sintf).await;

        Ok(dial_info)
    }

    async fn listen(
        &self,
        url: &url::Url,
        sintf: &str,
    ) -> Result<Option<TcpListener>, Box<dyn Error>> {
        let listener = match url.scheme() {
            "tcp" => {
                // Logic for listening on TCP
                let addr: SocketAddr = url.host_str().unwrap_or("0.0.0.0:0").parse()?;
                let tcp_listener = TcpListener::bind(addr).await?;
                Some(tcp_listener)
            }
            "tls" => {
                // Logic for listening on TLS
                None // Replace this with actual TLS listener creation
            }
            "unix" => {
                // Logic for listening on UNIX
                None // Replace this with actual UNIX listener creation
            }
            _ => {
                return Err(format!("unrecognized scheme {}", url.scheme()).into());
            }
        };

        Ok(listener)
    }
}

impl Link {
    fn get_inner(&self) -> MutexGuard<LinkInternal> {
        let inner = self.inner.lock().unwrap();
        inner
    }
    pub fn get_name(&self) -> String {
        self.get_inner().lname.clone()
    }

    pub fn get_remote_addr(&self) -> String {
        self.get_inner().conn.remote_addr.clone()
    }

    pub fn get_link_conn(&self) -> LinkConnHandle {
        self.get_inner().conn.clone()
    }

    pub async fn handler(
        &mut self,
        core: Arc<Core>,
        mut conn: LinkConn,
        dial: LinkDial,
    ) -> Result<(), Box<dyn Error>> {
        if self.links.is_connected_to(&self.get_inner().info) {
            return Ok(());
        }
        {
            self.links
                .links
                .lock()
                .unwrap()
                .remove(&self.get_inner().info);
        }
        let base = VersionMetadata::get_base_metadata(core.public.into());

        let mut meta_bytes = Vec::new();
        base.encode(&mut meta_bytes);
        //self.conn.conn.set_deadline(Some(Instant::now() + Duration::from_secs(6)))?;
        let n = { conn.write(&meta_bytes).await? };
        if n != meta_bytes.len() {
            return Err("incomplete handshake send".into());
        }
        let mut response = vec![0u8; meta_bytes.len()]; // Assuming the response is 40 bytes
        conn.read_exact(&mut response).await?;

        //        intf.conn.clear_deadline()?;
        let meta = VersionMetadata::decode(&response)?;
        if !meta.check() {
            let intf = self.get_inner();
            let connect_error = if intf.incoming {
                "Rejected incoming connection"
            } else {
                "Failed to connect"
            };
            let local_version = format!("{}.{}", base.ver, base.minor_ver);
            let remote_version = format!("{}.{}", meta.ver, meta.minor_ver);
            debug!(
                "{}: {} is incompatible version (local {}, remote {})",
                connect_error, intf.lname, local_version, remote_version,
            );
            return Err("remote node is incompatible version".into());
        }

        // Check if the remote side matches the keys we expected. This is a bit of a weak
        // check - in future versions we really should check a signature or something like that.

        let intf = (*self.get_inner()).clone();
        let pinned = &intf.options.pinned_ed25519_keys;
        if !pinned.is_empty() && !pinned.contains_key(&meta.key) {
            return Err("node public key that does not match pinned keys".into());
        }

        // Check if we're authorized to connect to this key / IP
        let allowed = &core.config.allowed_public_keys;
        let is_allowed = allowed.is_empty() || allowed.contains(&meta.key);
        if intf.incoming && !intf.force && !is_allowed {
            return Err(format!(
                "node public key {} is not in AllowedPublicKeys",
                hex::encode(meta.key.as_bytes())
            )
            .into());
        }

        {
            self.links
                .links
                .lock()
                .unwrap()
                .insert(self.get_inner().info.clone(), self.clone());
        }

        let dir = if intf.incoming { "inbound" } else { "outbound" };
        let remote_addr = address_to_ipv6(&addr_for_key(&meta.key).unwrap()).to_string();
        let remote_str = format!("{}@{}", remote_addr, intf.info.remote);
        let local_str = conn.conn.local_addr()?;
        info!(
            "Connected {} {}: {}, source {}",
            dir,
            intf.info.link_type.to_uppercase(),
            remote_str,
            local_str,
        );
        core.pconn
            .pconn
            .handle_conn(meta.key, conn.conn, intf.options.priority)
            .await;

        Ok(())
    }
}
