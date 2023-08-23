use ironwood_rs::network::crypto::PublicKeyBytes;
use std::collections::HashMap;

pub type ListenAddress = String;
type SourceInterface = String;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Peer {
    pub uri: String,
    pub source_interface: Option<SourceInterface>,
}

pub type NodeInfo = HashMap<String, serde_json::Value>;
pub type NodeInfoPrivacy = bool;
pub type AllowedPublicKey = PublicKeyBytes;

pub enum SetupOption {
    Peer(Peer),
    ListenAddress(ListenAddress),
    NodeInfo(NodeInfo),
    NodeInfoPrivacy(NodeInfoPrivacy),
    AllowedPublicKey(AllowedPublicKey),
    InterfaceName(String),
    InterfaceMTU(u16),
}
