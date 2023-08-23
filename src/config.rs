use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// NodeConfig is the main configuration structure, containing configuration
// options that are necessary for an Yggdrasil node to run. You will need to
// supply one of these structs to the Yggdrasil core when starting a node.
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct NodeConfig {
    #[serde(rename = "Peers")]
    pub peers: Vec<String>,
    #[serde(rename = "InterfacePeers")]
    pub interface_peers: HashMap<String, Vec<String>>,
    #[serde(rename = "Listen")]
    pub listen: Vec<String>,
    #[serde(rename = "AdminListen")]
    pub admin_listen: String,
    #[serde(rename = "MulticastInterfaces")]
    pub multicast_interfaces: Vec<MulticastInterfaceConfig>,
    #[serde(rename = "AllowedPublicKeys")]
    pub allowed_public_keys: Vec<String>,
    #[serde(rename = "PublicKey")]
    pub public_key: String,
    #[serde(rename = "PrivateKey")]
    pub private_key: String,
    #[serde(rename = "IfName")]
    pub if_name: String,
    #[serde(rename = "IfMTU")]
    pub if_mtu: u64,
    #[serde(rename = "NodeInfoPrivacy")]
    pub node_info_privacy: bool,
    #[serde(rename = "NodeInfo")]
    pub node_info: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MulticastInterfaceConfig {
    #[serde(rename = "Regex")]
    pub regex: String,
    #[serde(rename = "Beacon")]
    pub beacon: bool,
    #[serde(rename = "Listen")]
    pub listen: bool,
    #[serde(rename = "Port")]
    pub port: u16,
    #[serde(rename = "Priority")]
    pub priority: u64,
}

impl NodeConfig {
    // NewSigningKeys replaces the signing keypair in the NodeConfig with a new
    // signing keypair. The signing keys are used by the switch to derive the
    // structure of the spanning tree.
    pub fn new_keys(&mut self) {
        let mut csprng = OsRng {};
        let key_pair = ed25519_dalek::Keypair::generate(&mut csprng);
        self.public_key = hex::encode(key_pair.public.to_bytes());
        self.private_key = hex::encode(key_pair.secret.to_bytes()) + &self.public_key;
    }
}
