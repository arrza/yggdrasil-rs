use super::{
    nodeinfo::NodeInfo, Core, TYPE_PROTO_DEBUG, TYPE_PROTO_DUMMY, TYPE_PROTO_NODE_INFO_REQUEST,
    TYPE_PROTO_NODE_INFO_RESPONSE, TYPE_SESSION_PROTO,
};
use crate::address::{addr_for_key, address_to_ipv6};
use futures::channel::oneshot;
use ironwood_rs::{
    network::crypto::{PublicKeyBytes, PUBLIC_KEY_SIZE},
    types::Addr,
};
use log::debug;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    error::Error,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::time::timeout;

#[derive(Debug, PartialEq)]
pub enum DebugMessageType {
    Dummy = 0,
    GetSelfRequest = 1,
    GetSelfResponse = 2,
    GetPeersRequest = 3,
    GetPeersResponse = 4,
    GetDHTRequest = 5,
    GetDHTResponse = 6,
}

impl From<u8> for DebugMessageType {
    fn from(value: u8) -> Self {
        match value {
            0 => DebugMessageType::Dummy,
            1 => DebugMessageType::GetSelfRequest,
            2 => DebugMessageType::GetSelfResponse,
            3 => DebugMessageType::GetPeersRequest,
            4 => DebugMessageType::GetPeersResponse,
            5 => DebugMessageType::GetDHTRequest,
            6 => DebugMessageType::GetDHTResponse,
            _ => panic!("Invalid Debug Message"),
        }
    }
}

impl From<DebugMessageType> for u8 {
    fn from(val: DebugMessageType) -> Self {
        match val {
            DebugMessageType::Dummy => 0,
            DebugMessageType::GetSelfRequest => 1,
            DebugMessageType::GetSelfResponse => 2,
            DebugMessageType::GetPeersRequest => 3,
            DebugMessageType::GetPeersResponse => 4,
            DebugMessageType::GetDHTRequest => 5,
            DebugMessageType::GetDHTResponse => 6,
        }
    }
}
#[derive(Serialize, Deserialize)]
struct DebugGetSelfRequest {
    pub key: String,
}
type DebugGetSelfResponse = HashMap<String, Value>;

#[derive(Serialize, Deserialize)]
struct DebugGetPeersRequest {
    pub key: String,
}
type DebugGetPeersResponse = HashMap<String, Value>;

#[derive(Serialize, Deserialize)]
struct DebugGetDhtRequest {
    pub key: String,
}
type DebugGetDhtResponse = HashMap<String, Value>;

type RequestInfo = (Instant, oneshot::Sender<Value>);
#[derive(Clone)]
pub struct ProtoHandler {
    pub nodeinfo: NodeInfo,
    self_requests: Arc<Mutex<HashMap<PublicKeyBytes, RequestInfo>>>,
    peers_requests: Arc<Mutex<HashMap<PublicKeyBytes, RequestInfo>>>,
    dht_requests: Arc<Mutex<HashMap<PublicKeyBytes, RequestInfo>>>,
}

impl ProtoHandler {
    pub fn new() -> Self {
        Self {
            nodeinfo: NodeInfo::new(),
            self_requests: Arc::new(Mutex::new(HashMap::new())),
            peers_requests: Arc::new(Mutex::new(HashMap::new())),
            dht_requests: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    pub async fn handle_proto(
        self,
        core: Arc<Core>,
        key: PublicKeyBytes,
        bs: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        debug!("handle_proto: {} {:?}", key, bs);
        if bs.is_empty() {
            return Ok(());
        }
        match bs[0] {
            TYPE_PROTO_DUMMY => {}
            TYPE_PROTO_NODE_INFO_REQUEST => {
                self.nodeinfo.handle_req(core, key).await?;
            }
            TYPE_PROTO_NODE_INFO_RESPONSE => {
                debug!(
                    "TYPE_PROTO_NODE_INFO_RESPONSE: {}",
                    String::from_utf8_lossy(&bs[1..])
                );
                self.nodeinfo.handle_res(key, &bs[1..]).await?;
            }
            TYPE_PROTO_DEBUG => self.handle_debug(core, key, &bs[1..]).await?,
            _ => {}
        }
        Ok(())
    }
    async fn handle_debug(
        &self,
        core: Arc<Core>,
        key: PublicKeyBytes,
        bs: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        if bs.is_empty() {
            return Ok(());
        }
        match bs[0].into() {
            DebugMessageType::Dummy => Ok(()),
            DebugMessageType::GetSelfRequest => self.handle_get_self_request(core, key).await,
            DebugMessageType::GetSelfResponse => self.handle_get_self_response(key, &bs[1..]).await,
            DebugMessageType::GetPeersRequest => self.handle_get_peers_request(core, key).await,
            DebugMessageType::GetPeersResponse => {
                self.handle_get_peers_response(key, &bs[1..]).await
            }
            DebugMessageType::GetDHTRequest => self.handle_get_dht_request(core, key).await,
            DebugMessageType::GetDHTResponse => self.handle_get_dht_response(key, &bs[1..]).await,
        }
    }

    async fn send_debug(
        &self,
        core: Arc<Core>,
        key: PublicKeyBytes,
        d_type: DebugMessageType,
        data: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        let mut bs = vec![TYPE_SESSION_PROTO, TYPE_PROTO_DEBUG, d_type.into()];
        bs.extend_from_slice(data);
        core.pconn.write_to(&bs, Addr(key)).await
    }

    fn checked_insert(
        map: &mut HashMap<PublicKeyBytes, RequestInfo>,
        key: PublicKeyBytes,
        tx: oneshot::Sender<Value>,
    ) {
        map.retain(|_, (t, _)| t.elapsed().as_secs() < 6);
        map.insert(key, (Instant::now(), tx));
    }

    // Get self

    async fn send_get_self_request(
        &self,
        core: Arc<Core>,
        key: PublicKeyBytes,
    ) -> Result<oneshot::Receiver<Value>, Box<dyn Error>> {
        let (tx, rx) = oneshot::channel();
        Self::checked_insert(&mut self.self_requests.lock().unwrap(), key.clone(), tx);
        self.send_debug(core, key, DebugMessageType::GetSelfRequest, &[])
            .await?;
        Ok(rx)
    }

    async fn handle_get_self_request(
        &self,
        core: Arc<Core>,
        key: PublicKeyBytes,
    ) -> Result<(), Box<dyn Error>> {
        let self_ = core.get_self().await;
        let mut res = HashMap::new();
        res.insert("key", self_.key.to_string());
        res.insert(
            "coords",
            serde_json::to_string(&self_.coords)
                .unwrap()
                .replace(',', " "),
        );
        let bs = serde_json::to_vec(&res)?;
        self.send_debug(core, key, DebugMessageType::GetSelfResponse, &bs)
            .await
    }

    async fn handle_get_self_response(
        &self,
        key: PublicKeyBytes,
        bs: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        let mut callbacks = self.self_requests.lock().unwrap();
        if let Some((_, tx)) = callbacks.remove(&key) {
            let info: Value = serde_json::from_slice(bs)?;
            let _ = tx.send(info);
        }
        Ok(())
    }

    // Get peers
    async fn send_get_peers_request(
        &self,
        core: Arc<Core>,
        key: PublicKeyBytes,
    ) -> Result<oneshot::Receiver<Value>, Box<dyn Error>> {
        let (tx, rx) = oneshot::channel();
        Self::checked_insert(&mut self.peers_requests.lock().unwrap(), key.clone(), tx);
        self.send_debug(core, key, DebugMessageType::GetPeersRequest, &[])
            .await?;
        Ok(rx)
    }

    async fn handle_get_peers_request(
        &self,
        core: Arc<Core>,
        key: PublicKeyBytes,
    ) -> Result<(), Box<dyn Error>> {
        let peers = core.get_peers().await;
        let mut bs = Vec::new();
        for peer in peers {
            if bs.len() + peer.key.as_bytes().len() + 2 >= core.mtu() as usize {
                break;
            }
            bs.extend_from_slice(peer.key.as_bytes());
        }
        self.send_debug(core, key, DebugMessageType::GetPeersResponse, &bs)
            .await
    }

    async fn handle_get_peers_response(
        &self,
        key: PublicKeyBytes,
        bs: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        let mut callbacks = self.peers_requests.lock().unwrap();
        if let Some((_, tx)) = callbacks.remove(&key) {
            let mut keys = Vec::new();
            let mut bs = bs;
            while bs.len() >= PUBLIC_KEY_SIZE {
                let mut key_array = [0u8; PUBLIC_KEY_SIZE];
                key_array.copy_from_slice(&bs[..PUBLIC_KEY_SIZE]);
                keys.push(PublicKeyBytes(key_array).to_string());
                bs = &bs[PUBLIC_KEY_SIZE..];
            }
            let info: Value = serde_json::to_value(&keys)?;
            let _ = tx.send(info);
        }
        Ok(())
    }

    // Get DHT
    async fn send_get_dht_request(
        &self,
        core: Arc<Core>,
        key: PublicKeyBytes,
    ) -> Result<oneshot::Receiver<Value>, Box<dyn Error>> {
        let (tx, rx) = oneshot::channel();
        Self::checked_insert(&mut self.dht_requests.lock().unwrap(), key.clone(), tx);
        self.send_debug(core, key, DebugMessageType::GetDHTRequest, &[])
            .await?;
        Ok(rx)
    }

    async fn handle_get_dht_request(
        &self,
        core: Arc<Core>,
        key: PublicKeyBytes,
    ) -> Result<(), Box<dyn Error>> {
        let dht = core.pconn.pconn.core.dhtree.get_dht().await;
        let mut bs = Vec::new();
        for dht_info in dht {
            if bs.len() + dht_info.key.as_bytes().len() + 2 >= core.mtu() as usize {
                break;
            }
            bs.extend_from_slice(dht_info.key.as_bytes());
        }
        self.send_debug(core, key, DebugMessageType::GetDHTResponse, &bs)
            .await
    }

    async fn handle_get_dht_response(
        &self,
        key: PublicKeyBytes,
        bs: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        let mut callbacks = self.dht_requests.lock().unwrap();
        if let Some((_, tx)) = callbacks.remove(&key) {
            let mut keys = Vec::new();
            let mut bs = bs;
            while bs.len() >= PUBLIC_KEY_SIZE {
                let mut key_array = [0u8; PUBLIC_KEY_SIZE];
                key_array.copy_from_slice(&bs[..PUBLIC_KEY_SIZE]);
                keys.push(PublicKeyBytes(key_array).to_string());
                bs = &bs[PUBLIC_KEY_SIZE..];
            }
            let info: Value = serde_json::to_value(&keys)?;
            let _ = tx.send(info);
        }
        Ok(())
    }

    // Admin socket stuff for "Get self"

    pub async fn get_self_handler(
        &self,
        core: Arc<Core>,
        in_data: Value,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        debug!("get_self_handler: {}", in_data);
        let req: DebugGetSelfRequest = serde_json::from_value(in_data)?;
        let kbs = hex::decode(&req.key)?;
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&kbs[..32]);

        let rx = self
            .send_get_self_request(core, PublicKeyBytes(key_array))
            .await?;

        match timeout(Duration::from_secs(6), rx).await {
            Ok(Ok(msg)) => {
                let addr = address_to_ipv6(&addr_for_key(&PublicKeyBytes(key_array)).unwrap());
                let mut resp = DebugGetSelfResponse::new();
                resp.insert(addr.to_string(), msg);
                Ok(serde_json::to_value(resp)?)
            }
            _ => Err("Timed out waiting for response".into()),
        }
    }

    // Admin socket stuff for "Get peers"

    pub async fn get_peers_handler(
        &self,
        core: Arc<Core>,
        in_data: Value,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        debug!("get_peers_handler: {}", in_data);
        let req: DebugGetPeersRequest = serde_json::from_value(in_data)?;
        let kbs = hex::decode(&req.key)?;
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&kbs[..32]);

        let rx = self
            .send_get_peers_request(core, PublicKeyBytes(key_array))
            .await?;

        match timeout(Duration::from_secs(6), rx).await {
            Ok(Ok(msg)) => {
                let mut resp = DebugGetPeersResponse::new();
                resp.insert("keys".into(), msg);
                Ok(serde_json::to_value(resp)?)
            }
            _ => Err("Timed out waiting for response".into()),
        }
    }

    // Admin socket stuff for "Get DHT"
    pub async fn get_dht_handler(
        &self,
        core: Arc<Core>,
        in_data: Value,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        debug!("get_dht_handler: {}", in_data);
        let req: DebugGetDhtRequest = serde_json::from_value(in_data)?;
        let kbs = hex::decode(&req.key)?;
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&kbs[..32]);

        let rx = self
            .send_get_dht_request(core, PublicKeyBytes(key_array))
            .await?;

        match timeout(Duration::from_secs(6), rx).await {
            Ok(Ok(msg)) => {
                let mut resp = DebugGetDhtResponse::new();
                resp.insert("keys".into(), msg);
                Ok(serde_json::to_value(resp)?)
            }
            _ => Err("Timed out waiting for response".into()),
        }
    }
}
