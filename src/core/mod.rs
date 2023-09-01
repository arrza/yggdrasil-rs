mod link;
mod link_tcp;
mod nodeinfo;
mod options;
mod proto;

use ed25519_dalek::{PublicKey, SecretKey};
use ironwood_rs::{
    encrypted::{
        crypto::EdPriv,
        packetconn::{PacketConn, PacketConnRead},
    },
    network::packetconn::OobHandlerRx,
    types::Addr,
};
pub use options::{Peer, SetupOption};
use std::{
    cmp::min,
    collections::{HashMap, HashSet},
    error::Error,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::mpsc;

use self::{
    link::{LinkInfo, Links},
    options::{AllowedPublicKey, ListenAddress, NodeInfo, NodeInfoPrivacy},
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
    peers: HashMap<Peer, Option<LinkInfo>>,
    listeners: HashSet<ListenAddress>,
    nodeinfo: NodeInfo,
    nodeinfo_privacy: NodeInfoPrivacy,
    allowed_public_keys: HashSet<AllowedPublicKey>,
}

impl CoreConfig {
    fn _apply_option(&mut self, opt: SetupOption) {
        match opt {
            SetupOption::Peer(peer) => {
                self.peers.insert(peer, None);
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
    secret: EdPriv,
    pub public: PublicKey,
    config: CoreConfig,
    links: Links,
}

pub struct CoreRead {
    pub pconn: Arc<PacketConn>,
    //pub proto: ProtoHandler,
    pconn_read: PacketConnRead,
    secret: EdPriv,
    public: PublicKey,
}

impl CoreRead {
    pub fn mtu(&self) -> u64 {
        self.pconn.mtu() - 1
    }

    pub async fn read_from(&mut self, buf: &mut [u8]) -> Result<(usize, Addr), String> {
        loop {
            //let proto = self.proto.clone();
            let (n, type_, from) = self.pconn_read.read_from(buf).await?;
            if n == 0 {
                continue;
            }
            match type_ {
                TYPE_SESSION_TRAFFIC => {
                    let n = min(buf.len(), n);
                    return Ok((n, from));
                }
                TYPE_SESSION_PROTO => {
                    // handle protocol here
                    // proto.handle_proto(from.0, buf).await;
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
        };
        let core = Arc::new(core);
        //Add Peer Loop
        let core_cln = core.clone();
        tokio::spawn(async {
            let core = core_cln;
            loop {
                for (peer, _) in core.config.peers.iter() {
                    core.links
                        .call(
                            core.clone(),
                            &peer.uri.parse().unwrap(),
                            peer.source_interface.as_ref().map_or_else(|| "", |v| v),
                        )
                        .await;
                }
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });
        (
            core,
            CoreRead {
                pconn,
                pconn_read,
                secret: ed_secret,
                public: pub_key,
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
}
