use crate::version;

use super::{
    Core, TYPE_PROTO_NODE_INFO_REQUEST, TYPE_PROTO_NODE_INFO_RESPONSE, TYPE_SESSION_PROTO,
};
use ironwood_rs::{network::crypto::PublicKeyBytes, types::Addr};
use log::debug;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    error::Error,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{sync::oneshot, time::timeout};

#[derive(Serialize, Deserialize)]
struct GetNodeInfoRequest {
    key: String,
}
type GetNodeInfoResponse = HashMap<String, Value>;

#[derive(Clone)]
pub struct NodeInfo {
    my_node_info: Arc<Mutex<Value>>,
    callbacks: Arc<Mutex<HashMap<PublicKeyBytes, oneshot::Sender<Value>>>>,
}

impl NodeInfo {
    pub fn new() -> Self {
        Self {
            my_node_info: Arc::new(Mutex::new(Value::Null)),
            callbacks: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    pub fn set_node_info(
        &self,
        given: &Value,
        privacy: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut new_node_info = given.clone();

        if !privacy {
            new_node_info["buildname"] = version::build_name().into();
            new_node_info["buildversion"] = version::build_version().into();
            new_node_info["buildplatform"] = std::env::consts::OS.into();
            new_node_info["buildarch"] = std::env::consts::ARCH.into();
        }

        let new_json = serde_json::to_vec(&new_node_info)?;

        match new_json.len() {
            len if len > 16384 => Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "NodeInfo exceeds max length of 16384 bytes",
            ))),
            _ => {
                *self.my_node_info.lock().unwrap() = new_node_info;
                Ok(())
            }
        }
    }
    async fn send_req(
        &self,
        core: Arc<Core>,
        key: PublicKeyBytes,
    ) -> Result<oneshot::Receiver<Value>, Box<dyn Error>> {
        let (tx, rx) = oneshot::channel();
        let packet = [TYPE_SESSION_PROTO, TYPE_PROTO_NODE_INFO_REQUEST];
        core.pconn.write_to(&packet, Addr(key.clone())).await?;
        self.callbacks.lock().unwrap().insert(key, tx);
        Ok(rx)
    }

    async fn send_res(&self, core: Arc<Core>, key: PublicKeyBytes) -> Result<(), Box<dyn Error>> {
        let mut packet = vec![TYPE_SESSION_PROTO, TYPE_PROTO_NODE_INFO_RESPONSE];
        packet.append(&mut serde_json::to_vec(&*self.my_node_info.lock().unwrap()).unwrap());
        core.pconn.write_to(&packet, Addr(key)).await
    }
    pub async fn handle_req(
        &self,
        core: Arc<Core>,
        key: PublicKeyBytes,
    ) -> Result<(), Box<dyn Error>> {
        self.send_res(core, key).await
    }

    pub async fn handle_res(&self, key: PublicKeyBytes, bs: &[u8]) -> Result<(), Box<dyn Error>> {
        let mut callbacks = self.callbacks.lock().unwrap();
        if let Some(tx) = callbacks.remove(&key) {
            let info: Value = serde_json::from_slice(bs)?;
            tx.send(info);
        }
        Ok(())
    }

    pub async fn node_info_admin_handler(
        &self,
        core: Arc<Core>,
        in_data: Value,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        debug!("node_info_admin_handler: {}", in_data);
        let req: GetNodeInfoRequest = serde_json::from_value(in_data)?;
        let kbs = hex::decode(&req.key)?;
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&kbs[..32]);

        let rx = self.send_req(core, PublicKeyBytes(key_array)).await?;

        match timeout(Duration::from_secs(6), rx).await {
            Ok(Ok(msg)) => {
                let mut resp = GetNodeInfoResponse::new();
                resp.insert(req.key, msg);
                Ok(serde_json::to_value(resp)?)
            }
            _ => Err("Timed out waiting for response".into()),
        }
    }
}
