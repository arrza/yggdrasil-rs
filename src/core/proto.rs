use std::{error::Error, sync::Arc};

use ironwood_rs::{network::crypto::PublicKeyBytes, types::Addr};
use serde_json::Value;

use super::{
    nodeinfo::NodeInfo, Core, TYPE_PROTO_DEBUG, TYPE_PROTO_DUMMY, TYPE_PROTO_NODE_INFO_REQUEST,
    TYPE_PROTO_NODE_INFO_RESPONSE, TYPE_SESSION_PROTO,
};

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

#[derive(Clone)]
pub struct ProtoHandler {
    core: Arc<Core>,
    nodeinfo: NodeInfo,
}

impl ProtoHandler {
    pub async fn handle_proto(self, key: PublicKeyBytes, bs: &[u8]) -> Result<(), Box<dyn Error>> {
        if bs.is_empty() {
            return Ok(());
        }
        match bs[0] {
            TYPE_PROTO_DUMMY => {}
            TYPE_PROTO_NODE_INFO_REQUEST => {
                self.nodeinfo.handle_req(key).await?;
            }
            TYPE_PROTO_NODE_INFO_RESPONSE => {
                let info: Value = serde_json::from_slice(&bs[1..])?;
                self.nodeinfo.handle_res(key, info).await?;
            }
            TYPE_PROTO_DEBUG => self.handle_debug(key, &bs[1..]).await?,
            _ => {}
        }
        Ok(())
    }
    async fn handle_debug(&self, key: PublicKeyBytes, bs: &[u8]) -> Result<(), Box<dyn Error>> {
        if bs.is_empty() {
            return Ok(());
        }
        match bs[0].into() {
            DebugMessageType::Dummy => {}
            DebugMessageType::GetSelfRequest => todo!(),
            DebugMessageType::GetSelfResponse => todo!(),
            DebugMessageType::GetPeersRequest => todo!(),
            DebugMessageType::GetPeersResponse => todo!(),
            DebugMessageType::GetDHTRequest => todo!(),
            DebugMessageType::GetDHTResponse => todo!(),
        }
        Ok(())
    }

    async fn send_febug(
        &self,
        key: PublicKeyBytes,
        d_type: u8,
        data: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        let mut bs = vec![TYPE_SESSION_PROTO, TYPE_PROTO_DEBUG, d_type];
        bs.extend_from_slice(data);
        self.core.write_to(&bs, Addr(key)).await
    }

    // async fn handle_self_request(&self, key: PublicKeyBytes,)-> Result<(), Box<dyn Error>> {
    //     self.core.
    // }
}
