use crate::{
    address::{addr_for_key, address_to_ipv6},
    version::VersionMetadata,
    Core,
};
use ironwood_rs::{
    network::{
        crypto::PublicKeyBytes,
        wire::{Decode, Encode},
    },
    types::{close_channel, CloseChannelRx, CloseChannelTx, Conn, IrwdError},
};
use log::{debug, info};
use std::{
    collections::HashMap,
    error::Error,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, MutexGuard,
    },
    time::Instant,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpListener,
    sync::oneshot,
};
use url::Url;

use super::{link_tcp::LinkTCP, link_tls::LinkTLS, options::ListenAddress};

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

#[derive(Clone, Default)]
pub struct LinkOptions {
    pub pinned_ed25519_keys: HashMap<PublicKeyBytes, ()>,
    pub priority: u8,
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

#[derive(Debug)]
pub struct LinkConn<T: Conn> {
    rx: Arc<AtomicU64>,
    tx: Arc<AtomicU64>,
    up: Arc<Instant>,
    conn: T,
}

impl<T: Conn> LinkConn<T> {
    fn new(conn: T) -> Self {
        LinkConn {
            rx: Arc::new(AtomicU64::new(0)),
            tx: Arc::new(AtomicU64::new(0)),
            up: Arc::new(Instant::now()),
            conn,
        }
    }
    fn handle(&self) -> (LinkConnHandle, CloseChannelRx) {
        let (tx, rx) = close_channel();
        (
            LinkConnHandle {
                rx: self.rx.clone(),
                tx: self.tx.clone(),
                up: self.up.clone(),
                remote_addr: self.conn.peer_addr().unwrap().to_string(),
                close: tx,
            },
            rx,
        )
    }
}

impl<T: Conn> Conn for LinkConn<T> {
    fn local_addr(&self) -> Result<String, IrwdError> {
        self.conn.local_addr()
    }

    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn AsyncRead + Unpin + Send + Sync>,
        Box<dyn AsyncWrite + Unpin + Send + Sync>,
    ) {
        let (rx, tx) = Box::new(self.conn).split();
        (
            Box::new(LinkConnRead {
                rx: self.rx,
                conn: rx,
            }),
            Box::new(LinkConnWrite {
                tx: self.tx,
                conn: tx,
            }),
        )
    }

    fn peer_addr(&self) -> Result<String, IrwdError> {
        self.conn.peer_addr()
    }
}

impl<T: Conn> AsyncRead for LinkConn<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let initial_rem = buf.remaining();
        let self_ = self.get_mut();
        let conn = &mut self_.conn;
        let res = Pin::new(conn).poll_read(cx, buf);
        if let std::task::Poll::Ready(Ok(())) = res {
            let read = initial_rem - buf.remaining();
            self_.rx.fetch_add(read as u64, Ordering::Relaxed);
        }
        res
    }
}

impl<T: Conn> AsyncWrite for LinkConn<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        let self_ = self.get_mut();
        let conn = &mut self_.conn;
        let res = Pin::new(conn).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(n)) = res {
            self_.tx.fetch_add(n as u64, Ordering::Relaxed);
        }
        res
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let self_ = self.get_mut();
        let conn = &mut self_.conn;
        Pin::new(conn).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let self_ = self.get_mut();
        let conn = &mut self_.conn;
        Pin::new(conn).poll_shutdown(cx)
    }
}

#[derive(Debug)]
pub struct LinkConnRead<T: AsyncRead + Unpin + Send + Sync> {
    rx: Arc<AtomicU64>,
    conn: T,
}
impl<T: AsyncRead + Unpin + Send + Sync> AsyncRead for LinkConnRead<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let initial_rem = buf.remaining();
        let self_ = self.get_mut();
        let conn = &mut self_.conn;
        let res = Pin::new(conn).poll_read(cx, buf);
        if let std::task::Poll::Ready(Ok(())) = res {
            let read = initial_rem - buf.remaining();
            self_.rx.fetch_add(read as u64, Ordering::Relaxed);
        }
        res
    }
}

#[derive(Debug)]
pub struct LinkConnWrite<T: AsyncWrite + Unpin + Send + Sync> {
    tx: Arc<AtomicU64>,
    conn: T,
}
impl<T: AsyncWrite + Unpin + Send + Sync> AsyncWrite for LinkConnWrite<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        let self_ = self.get_mut();
        let conn = &mut self_.conn;
        let res = Pin::new(conn).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(n)) = res {
            self_.tx.fetch_add(n as u64, Ordering::Relaxed);
        }
        res
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let self_ = self.get_mut();
        let conn = &mut self_.conn;
        Pin::new(conn).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let self_ = self.get_mut();
        let conn = &mut self_.conn;
        Pin::new(conn).poll_shutdown(cx)
    }
}
#[derive(Clone)]
pub struct LinkConnHandle {
    pub rx: Arc<AtomicU64>,
    pub tx: Arc<AtomicU64>,
    pub up: Arc<Instant>,
    pub remote_addr: String,
    pub close: CloseChannelTx,
}

impl Links {
    pub async fn create<T: Conn + 'static>(
        &self,
        core: Arc<Core>,
        conn: T,
        dial: LinkDial,
        name: String,
        info: LinkInfo,
        incoming: bool,
        force: bool,
        options: LinkOptions,
    ) -> Result<(), Box<dyn std::error::Error>> {
        debug!("++create");
        let conn = LinkConn::new(conn);
        let (conn_handle, close) = conn.handle();
        let mut intf = Link {
            links: self.clone(),
            inner: Arc::new(Mutex::new(LinkInternal {
                conn: conn_handle,
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
            if let Err(err) = intf.handler(core, conn, dial, close).await {
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
            local: sintf.to_string(), // Update this with the actual local address
            remote: url.host_str().unwrap_or("").to_string()
                + ":"
                + url.port().unwrap_or(0).to_string().as_str(),
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
        match info.link_type.as_str() {
            "tcp" => {
                // Logic for dialing on TCP
                let tcp_link = LinkTCP {
                    links: self.clone(),
                };
                tcp_link.dial(core, url, options, sintf).await?;
            }
            "tls" => {
                // SNI headers must contain hostnames and not IP addresses, so we must make sure
                // that we do not populate the SNI with an IP literal. We do this by splitting
                // the host-port combo from the query option and then seeing if it parses to an
                // IP address successfully or not.

                let mut tls_sni = String::new();
                if let Some((_, sni)) = url.query_pairs().find(|(key, _)| key == "sni") {
                    if sni.parse::<IpAddr>().is_err() {
                        tls_sni = sni.into();
                    }
                }

                // If the SNI is not configured still because the above failed then we'll try
                // again but this time we'll use the host part of the peering URI instead.
                if tls_sni.is_empty() {
                    if let Some(host) = url.host_str() {
                        if host.parse::<IpAddr>().is_err() {
                            tls_sni = host.into();
                        }
                    }
                }

                // Logic for dialing on TCP
                let tls_link = LinkTLS {
                    links: self.clone(),
                };
                tls_link.dial(core, url, options, sintf, &tls_sni).await?;
            }
            "unix" => {
                // Logic for dialing on UNIX
                // Replace this with actual UNIX dialing
            }
            _ => {
                return Err(format!("unrecognized scheme {}", url.scheme()).into());
            }
        };

        Ok(dial_info)
    }

    pub async fn listen(
        &self,
        core: Arc<Core>,
        url: &url::Url,
        sintf: &str,
    ) -> Result<(), Box<dyn Error>> {
        match url.scheme() {
            "tcp" => {
                // Logic for listening on TCP
                let tcp_link = LinkTCP {
                    links: self.clone(),
                };
                tcp_link.listen(core, url, sintf).await?;
            }
            "tls" => {
                // Logic for listening on TLS
                let tls_link = LinkTLS {
                    links: self.clone(),
                };
                tls_link.listen(core, url, sintf).await?;
            }
            "unix" => {
                // Logic for listening on UNIX
                // Replace this with actual UNIX listener creation
            }
            _ => {
                return Err(format!("unrecognized scheme {}", url.scheme()).into());
            }
        };

        Ok(())
    }
}

impl Link {
    fn get_inner(&self) -> MutexGuard<LinkInternal> {
        let inner: MutexGuard<'_, LinkInternal> = self.inner.lock().unwrap();
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

    pub async fn close(&self) {
        let close = { self.get_inner().conn.close.clone() };
        close.send(()).await.unwrap();
        close.closed().await;
    }

    pub async fn handler<T: Conn + 'static>(
        &mut self,
        core: Arc<Core>,
        mut conn: LinkConn<T>,
        dial: LinkDial,
        close: CloseChannelRx,
    ) -> Result<(), String> {
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
        let n = { conn.write(&meta_bytes).await.map_err(|e| e.to_string())? };
        if n != meta_bytes.len() {
            return Err("incomplete handshake send".into());
        }
        let mut response = vec![0u8; meta_bytes.len()]; // Assuming the response is 40 bytes
        conn.read_exact(&mut response)
            .await
            .map_err(|e| e.to_string())?;

        //        intf.conn.clear_deadline()?;
        let meta = VersionMetadata::decode(&response).map_err(|e| e.to_string())?;
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
        let local_str = conn.conn.local_addr().map_err(|e| e.to_string())?;
        info!(
            "Connected {} {}: {}, source {}",
            dir,
            intf.info.link_type.to_uppercase(),
            remote_str,
            local_str,
        );
        core.pconn
            .pconn
            .handle_conn(meta.key, Box::new(conn), intf.options.priority, close)
            .await;

        Ok(())
    }
}

pub fn link_options_for_listener(url: &url::Url) -> LinkOptions {
    if let Some((_, prio)) = url.query_pairs().find(|(key, _)| key == "priority") {
        if let Ok(prio) = prio.parse() {
            return LinkOptions {
                priority: prio,
                ..Default::default()
            };
        }
    }
    LinkOptions::default()
}
