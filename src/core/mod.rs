mod api;
mod link;
mod link_tcp;
mod link_tls;
mod nodeinfo;
mod options;
mod proto;

use ed25519_dalek::{PublicKey, SecretKey};
use ipnet::Ipv6Net;
use ironwood_rs::{
    encrypted::{
        crypto::EdPriv,
        packetconn::{PacketConn, PacketConnRead},
    },
    network::packetconn::OobHandlerRx,
    types::Addr,
};
use log::error;
pub use options::{Peer, SetupOption};
use std::{
    cmp::min,
    collections::{HashMap, HashSet},
    error::Error,
    net::Ipv6Addr,
    sync::{atomic::Ordering, Arc, Mutex},
    time::Duration,
};
use tokio::sync::mpsc;
use url::Url;

use crate::{
    address::{addr_for_key, address_to_ipv6, subnet_for_key, subnet_to_ipv6},
    admin::AdminSocket,
    error::YggErrors,
};

use self::{
    link::{LinkInfo, Links},
    options::{AllowedPublicKey, ListenAddress, NodeInfo, NodeInfoPrivacy},
    proto::ProtoHandler,
};

// Packet types
const TYPE_SESSION_DUMMY: u8 = 0;
const TYPE_SESSION_TRAFFIC: u8 = 1;
const TYPE_SESSION_PROTO: u8 = 2;

const TYPE_PROTO_DUMMY: u8 = 0;
const TYPE_PROTO_NODE_INFO_REQUEST: u8 = 1;
const TYPE_PROTO_NODE_INFO_RESPONSE: u8 = 2;
const TYPE_PROTO_DEBUG: u8 = 255;

#[derive(Debug, Clone, Default)]
struct CoreConfig {
    peers: Arc<Mutex<HashMap<Peer, Option<LinkInfo>>>>,
    listeners: HashSet<ListenAddress>,
    nodeinfo: NodeInfo,
    nodeinfo_privacy: NodeInfoPrivacy,
    allowed_public_keys: HashSet<AllowedPublicKey>,
}

impl CoreConfig {
    fn _apply_option(&mut self, opt: SetupOption) {
        match opt {
            SetupOption::Peer(peer) => {
                self.peers.lock().unwrap().insert(peer, None);
            }
            SetupOption::ListenAddress(address) => {
                self.listeners.insert(address);
            }
            SetupOption::NodeInfo(info) => {
                self.nodeinfo = info;
            }
            SetupOption::NodeInfoPrivacy(privacy) => {
                self.nodeinfo_privacy = privacy;
            }
            SetupOption::AllowedPublicKey(pk) => {
                self.allowed_public_keys.insert(pk);
            }
            _ => {}
        }
    }
}

#[derive(Clone)]
pub struct Core {
    pub pconn: Arc<PacketConn>,
    pub secret: EdPriv,
    pub public: PublicKey,
    config: CoreConfig,
    links: Links,
    proto: ProtoHandler,
}

pub struct CoreRead {
    pub pconn: Arc<PacketConn>,
    proto: ProtoHandler,
    pconn_read: PacketConnRead,
    secret: EdPriv,
    public: PublicKey,
}

impl CoreRead {
    pub fn mtu(&self) -> u64 {
        self.pconn.mtu() - 1
    }

    pub async fn read_from(
        &mut self,
        core: Arc<Core>,
        buf: &mut [u8],
    ) -> Result<(usize, Addr), String> {
        loop {
            let proto = self.proto.clone();
            let (n, type_, from) = self.pconn_read.read_from(buf).await?;
            if n == 0 {
                continue;
            }
            let n = min(buf.len(), n);
            match type_ {
                TYPE_SESSION_TRAFFIC => {
                    return Ok((n, from));
                }
                TYPE_SESSION_PROTO => {
                    // handle protocol here
                    if let Err(e) = proto.handle_proto(core.clone(), from.0, &buf[..n]).await {
                        error!("Error in handling proto: {}", e);
                    }
                    continue;
                }
                _ => continue,
            }
        }
    }
}

impl Core {
    pub async fn new(
        secret: &SecretKey,
        opts: Vec<SetupOption>,
    ) -> (Arc<Core>, CoreRead, OobHandlerRx) {
        let mut ed_secret = [0; 64];
        ed_secret[..32].copy_from_slice(secret.as_bytes());
        let pub_key: PublicKey = secret.into();
        ed_secret[32..].copy_from_slice(pub_key.as_bytes());
        let ed_secret = EdPriv::from_slice(&ed_secret).unwrap();
        let mut config = CoreConfig::default();
        for opt in opts {
            config._apply_option(opt);
        }

        let (oob_handler_tx, oob_handler_rx) = mpsc::channel(10);
        let (pconn, pconn_read) = PacketConn::new(secret, Some(oob_handler_tx)).await;
        let core = Core {
            pconn: pconn.clone(),
            secret: ed_secret.clone(),
            public: pub_key,
            config,
            links: Links {
                links: Arc::new(Mutex::new(HashMap::new())),
            },
            proto: ProtoHandler::new(),
        };

        let core = Arc::new(core);
        core.proto
            .nodeinfo
            .set_node_info(
                &serde_json::to_value(&core.config.nodeinfo).unwrap(),
                core.config.nodeinfo_privacy,
            )
            .unwrap();
        for listener in core.config.listeners.iter() {
            if let Err(e) = core
                .links
                .listen(core.clone(), &listener.parse::<url::Url>().unwrap(), "")
                .await
            {
                error!("Can not listen on {} with error {}", listener, e);
            }
        }

        //Add Peer Loop
        let core_cln = core.clone();
        tokio::spawn(async {
            let core = core_cln;
            loop {
                let peers: Vec<_> = core.config.peers.lock().unwrap().keys().cloned().collect();
                for peer in peers {
                    match core
                        .links
                        .call(
                            core.clone(),
                            &peer.uri.parse().unwrap(),
                            peer.source_interface.as_ref().map_or_else(|| "", |v| v),
                        )
                        .await
                    {
                        Ok(link_info) => {
                            let mut peers = core.config.peers.lock().unwrap();
                            peers.insert(peer, Some(link_info));
                        }
                        Err(e) => {
                            error!("Can not connect to peer {} with error {}", peer.uri, e);
                        }
                    }
                }
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });
        let proto = core.proto.clone();
        (
            core,
            CoreRead {
                pconn,
                pconn_read,
                secret: ed_secret,
                public: pub_key,
                proto,
            },
            oob_handler_rx,
        )
    }

    pub fn mtu(&self) -> u64 {
        self.pconn.mtu() - 1
    }

    pub async fn write_to(&self, p: &[u8], addr: Addr) -> Result<(), Box<dyn Error>> {
        let mut buf = Vec::new();
        buf.push(TYPE_SESSION_TRAFFIC);
        buf.extend_from_slice(p);
        self.pconn.write_to(&buf, addr).await?;
        Ok(())
    }

    pub fn address(&self) -> Ipv6Addr {
        address_to_ipv6(&addr_for_key(&self.pconn.pconn.core.crypto.public_key).unwrap())
    }

    pub fn subnet(&self) -> Ipv6Net {
        let ipv6 =
            subnet_to_ipv6(&subnet_for_key(&self.pconn.pconn.core.crypto.public_key).unwrap());
        Ipv6Net::new(ipv6, 64).unwrap()
    }

    pub async fn get_self(&self) -> api::SelfInfo {
        let self_ = self.pconn.pconn.core.dhtree.get_self().await;
        api::SelfInfo {
            key: self_.key,
            root: self_.root,
            coords: self_.coords,
        }
    }
    pub async fn get_peers(&self) -> Vec<api::PeerInfo> {
        let peers = self.pconn.pconn.core.dhtree.get_peers().await;
        let mut peer_infos = Vec::new();
        let mut names = HashMap::new();
        {
            let links = self.links.links.lock().unwrap();
            for (_, link) in links.iter() {
                names.insert(
                    link.get_remote_addr(),
                    (link.get_name(), link.get_link_conn()),
                );
            }
        }
        for peer in peers {
            let (name, link_conn) = names.get(&peer.remote_addr).unwrap();
            peer_infos.push(api::PeerInfo {
                key: peer.key,
                root: peer.root,
                coords: peer.coords,
                port: peer.port as u16,
                priority: peer.priority,
                remote: name.to_string(),
                rx_bytes: link_conn.rx.load(Ordering::Relaxed),
                tx_bytes: link_conn.tx.load(Ordering::Relaxed),
                uptime: link_conn.up.elapsed(),
            });
        }
        peer_infos
    }

    pub async fn add_peer(
        self: Arc<Self>,
        uri: &str,
        source_interface: Option<&str>,
    ) -> Result<(), YggErrors> {
        let sintf = source_interface.map(|v| v.to_string());
        let peer = Peer {
            uri: uri.to_string(),
            source_interface: sintf,
        };
        if self.config.peers.lock().unwrap().contains_key(&peer) {
            return Err(YggErrors::PeerAlreadyConfigured);
        }

        let url = Url::parse(uri).unwrap();
        let link_info = self
            .links
            .call(
                self.clone(),
                &url,
                source_interface.map_or_else(|| "", |v| v),
            )
            .await
            .map_err(|e| YggErrors::Other(e))?;
        self.config
            .peers
            .lock()
            .unwrap()
            .insert(peer, Some(link_info));
        Ok(())
    }

    pub async fn remove_peer(
        self: Arc<Self>,
        uri: &str,
        source_interface: Option<&str>,
    ) -> Result<(), YggErrors> {
        let sintf = source_interface.map(|v| v.to_string());
        let peer = Peer {
            uri: uri.to_string(),
            source_interface: sintf,
        };
        if !self.config.peers.lock().unwrap().contains_key(&peer) {
            return Err(YggErrors::PeerNotConfigured);
        }
        let link = if let Some(link_info) = self.config.peers.lock().unwrap().remove(&peer).unwrap()
        {
            let mut links = self.links.links.lock().unwrap();
            links.remove(&link_info)
        } else {
            None
        };
        if let Some(link) = link {
            link.close().await;
            println!("Peer removed {}", peer.uri);
        }
        Ok(())
    }

    pub fn set_admin(self: Arc<Core>, a: &AdminSocket) {
        let core = self.clone();
        a.add_handler(
            "getNodeInfo".into(),
            "Request nodeinfo from a remote node by its public key".into(),
            vec!["key".into()],
            Box::new(move |args| {
                let core = core.clone();
                Box::pin(async move {
                    core.proto
                        .nodeinfo
                        .node_info_admin_handler(core.clone(), args)
                        .await
                        .map_err(|e| e.to_string())
                })
            }),
        );
        let core = self.clone();
        a.add_handler(
            "debug_remoteGetSelf".into(),
            "Debug use only".into(),
            vec!["key".into()],
            Box::new(move |args| {
                let core = core.clone();
                Box::pin(async move {
                    core.proto
                        .get_self_handler(core.clone(), args)
                        .await
                        .map_err(|e| e.to_string())
                })
            }),
        );
        let core = self.clone();
        a.add_handler(
            "debug_remoteGetPeers".into(),
            "Debug use only".into(),
            vec!["key".into()],
            Box::new(move |args| {
                let core = core.clone();
                Box::pin(async move {
                    core.proto
                        .get_peers_handler(core.clone(), args)
                        .await
                        .map_err(|e| e.to_string())
                })
            }),
        );
        let core = self.clone();
        a.add_handler(
            "debug_remoteGetDHT".into(),
            "Debug use only".into(),
            vec!["key".into()],
            Box::new(move |args| {
                let core = core.clone();
                Box::pin(async move {
                    core.proto
                        .get_dht_handler(core.clone(), args)
                        .await
                        .map_err(|e| e.to_string())
                })
            }),
        );
    }
}
