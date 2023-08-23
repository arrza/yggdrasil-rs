use crate::version;

use super::{
    Core, TYPE_PROTO_NODE_INFO_REQUEST, TYPE_PROTO_NODE_INFO_RESPONSE, TYPE_SESSION_PROTO,
};
use ironwood_rs::{network::crypto::PublicKeyBytes, types::Addr};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    error::Error,
    sync::{Arc, Mutex},
};
use tokio::sync::oneshot;

#[derive(Serialize, Deserialize)]
struct GetNodeInfoRequest {
    key: String,
}
type GetNodeInfoResponse = Value;

#[derive(Clone)]
pub struct NodeInfo {
    core: Arc<Core>,
    my_node_info: Value,
    callbacks: Arc<Mutex<HashMap<PublicKeyBytes, oneshot::Sender<Value>>>>,
}

impl NodeInfo {
    pub fn set_node_info(
        &mut self,
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
                self.my_node_info = new_node_info;
                Ok(())
            }
        }
    }
    async fn send_req(&self, key: PublicKeyBytes) -> Result<(), Box<dyn Error>> {
        let packet = [TYPE_SESSION_PROTO, TYPE_PROTO_NODE_INFO_REQUEST];
        self.core.write_to(&packet, Addr(key)).await
    }

    async fn send_res(&self, key: PublicKeyBytes) -> Result<(), Box<dyn Error>> {
        let mut packet = vec![TYPE_SESSION_PROTO, TYPE_PROTO_NODE_INFO_RESPONSE];
        packet.append(&mut serde_json::to_vec(&self.my_node_info).unwrap());
        self.core.write_to(&packet, Addr(key)).await
    }
    pub async fn handle_req(&self, key: PublicKeyBytes) -> Result<(), Box<dyn Error>> {
        self.send_res(key).await
    }

    pub async fn handle_res(&self, key: PublicKeyBytes, info: Value) -> Result<(), Box<dyn Error>> {
        let mut callbacks = self.callbacks.lock().unwrap();
        if let Some(tx) = callbacks.remove(&key) {
            tx.send(info);
        }
        Ok(())
    }

    async fn node_info_admin_handler(
        &mut self,
        in_data: &[u8],
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let req: GetNodeInfoRequest = serde_json::from_slice(in_data)?;
        let kbs = hex::decode(req.key)?;
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&kbs[..32]);

        self.send_req(PublicKeyBytes(key_array)).await;

        // let timer = std::time::Duration::from_secs(6);
        // match receiver.recv_timeout(timer) {
        //     Ok(info) => {
        //         let msg: Value = serde_json::from_slice(&info)?;
        //         let key_hex = hex::encode(kbs);
        //         let mut res = GetNodeInfoResponse::new();
        //         res.insert(key_hex, msg);
        //         Ok(json!(res))
        //     }
        //     Err(_) => Err("Timed out waiting for response".into()),
        // }
        Ok(Value::String("test".to_string()))
    }
}
