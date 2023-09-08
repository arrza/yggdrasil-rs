use std::{
    collections::HashMap,
    os::unix::prelude::MetadataExt,
    path::Path,
    pin::Pin,
    sync::{Arc, RwLock},
};

use crate::{
    address::{addr_for_key, address_to_ipv6},
    core::Core,
    version::{build_name, build_version},
};
use futures::{Future, SinkExt};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::net::{TcpListener, UnixListener};
use tokio_serde::{formats::SymmetricalJson, SymmetricallyFramed};
use tokio_stream::{
    wrappers::{TcpListenerStream, UnixListenerStream},
    StreamExt,
};
use tokio_util::codec::{BytesCodec, FramedRead, FramedWrite};
use url::Url;

// TODO: Add authentication
type HandlerFunc =
    Box<dyn Fn(Value) -> Pin<Box<dyn Future<Output = Value> + Send + 'static>> + Sync + Send>;
struct Handler {
    func: HandlerFunc,
    desc: String,
    args: Vec<String>,
}

#[derive(Clone)]
pub struct AdminSocket {
    pub core: Arc<Core>,
    handlers: Arc<RwLock<HashMap<String, Handler>>>,
    pub listen_addr: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AdminSocketRequest {
    request: String,
    arguments: Option<Value>,
    keepalive: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AdminSocketResponse {
    status: String,
    error: Option<String>,
    request: Value,
    response: Value,
}

#[derive(Debug, Serialize, Deserialize)]
struct ListResponse {
    list: Vec<ListEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ListEntry {
    command: String,
    description: String,
    fields: Option<Vec<String>>,
}

enum Listener {
    Tcp(TcpListener),
    Unix(UnixListener),
}

impl AdminSocket {
    pub fn new(core: Arc<Core>, listen_addr: String) -> Self {
        let mut a = Self {
            core,
            listen_addr,
            handlers: Arc::new(RwLock::new(HashMap::new())),
        };
        let a_cln = a.clone();
        a.add_handler(
            "list".into(),
            "List available commands".into(),
            vec![],
            Box::new(move |_| {
                let mut list = vec![];
                for (name, handler) in a_cln.handlers.read().unwrap().iter() {
                    list.push(ListEntry {
                        command: name.clone(),
                        description: handler.desc.clone(),
                        fields: Some(handler.args.clone()),
                    });
                }
                list.sort_by(|a, b| a.command.cmp(&b.command));

                Box::pin(async move { serde_json::to_value(ListResponse { list }).unwrap() })
            }),
        );
        a
    }

    pub fn setup_admin_handlers(&mut self) {
        let core = self.core.clone();
        self.add_handler(
            "getSelf".into(),
            "Show details about this node".into(),
            vec![],
            Box::new(move |_| {
                let core = core.clone();
                Box::pin(async move {
                    let self_ = get_self_handler(core).await;
                    serde_json::to_value(self_).unwrap()
                })
            }),
        );
        let core = self.core.clone();
        self.add_handler(
            "getPeers".into(),
            "Show directly connected peers".into(),
            vec![],
            Box::new(move |_| {
                let core = core.clone();
                Box::pin(async move {
                    let peers = get_peers_handler(core).await;
                    serde_json::to_value(peers).unwrap()
                })
            }),
        );
        let core = self.core.clone();
        self.add_handler(
            "getDHT".into(),
            "Show known DHT entries".into(),
            vec![],
            Box::new(move |_| {
                let core = core.clone();
                Box::pin(async move {
                    let dht = get_dht_handler(core).await;
                    serde_json::to_value(dht).unwrap()
                })
            }),
        );
        let core = self.core.clone();
        self.add_handler(
            "getPaths".into(),
            "Show established paths through this node".into(),
            vec![],
            Box::new(move |_| {
                let core = core.clone();
                Box::pin(async move {
                    let paths = get_paths_handler(core).await;
                    serde_json::to_value(paths).unwrap()
                })
            }),
        );
    }

    pub fn add_handler(
        &mut self,
        name: String,
        desc: String,
        args: Vec<String>,
        handler: HandlerFunc,
    ) {
        self.handlers.write().unwrap().insert(
            name.to_lowercase(),
            Handler {
                func: handler,
                desc,
                args,
            },
        );
    }

    pub async fn listen(self) -> Result<(), String> {
        let listenaddr = &self.listen_addr;
        let url = Url::parse(listenaddr).map_err(|e| e.to_string())?;
        let listener = match url.scheme() {
            "unix" => {
                // Handle Unix domain socket here.
                let path = Path::new(url.path());
                // Handle Unix domain socket here.
                if path.exists() {
                    debug!(
                        "Admin socket {} already exists, trying to clean up",
                        path.display()
                    );
                    match UnixListener::bind(path) {
                        Ok(_) => {
                            error!(
                                "Admin socket {} already exists and is in use by another process",
                                path.display()
                            );
                            std::process::exit(1);
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::TimedOut => {
                            let remove_result = std::fs::remove_file(path);
                            match remove_result {
                                Ok(_) => debug!("Admin socket {} was cleaned up", path.display()),
                                Err(remove_err) => {
                                    error!(
                                        "Admin socket {} already exists and was not cleaned up: {}",
                                        path.display(),
                                        remove_err
                                    );
                                    std::process::exit(1);
                                }
                            }
                        }
                        Err(err) => {
                            error!(
                                "Error connecting to admin socket {}: {}",
                                path.display(),
                                err
                            );
                            std::process::exit(1);
                        }
                    }
                }
                match UnixListener::bind(path) {
                    Ok(listener) => {
                        // Handle permission settings here.
                        let mode = path.metadata().map(|m| m.mode()).unwrap_or(0o660);
                        if !path.is_file() {
                            warn!("WARNING: {} may have unsafe permissions!", path.display());
                        }
                        Listener::Unix(listener)
                    }
                    Err(err) => {
                        error!("Admin socket failed to listen: {}", err);
                        return Err(err.to_string());
                    }
                }
            }
            "tcp" => {
                // Handle TCP socket here.
                match TcpListener::bind(&*url.socket_addrs(|| None).unwrap()).await {
                    Ok(listener) => Listener::Tcp(listener),
                    Err(err) => {
                        error!("Admin socket failed to listen: {}", err);
                        return Err(err.to_string());
                    }
                }
            }
            _ => {
                // Handle unsupported scheme.
                return Err("Unsupported scheme".into());
            }
        };

        tokio::spawn(async move {
            match listener {
                Listener::Tcp(listener) => {
                    let mut listener = TcpListenerStream::new(listener);
                    loop {
                        match listener.next().await {
                            Some(Ok(mut conn)) => {
                                // Handle connection here.
                                // Wrap the socket in framed I/O using tokio-serde.
                                let (conn_rx, conn_tx) = conn.split();
                                let framed_rx = FramedRead::new(conn_rx, BytesCodec::new());
                                let mut framed_rx = SymmetricallyFramed::new(
                                    framed_rx,
                                    SymmetricalJson::<Value>::default(),
                                );
                                // Read an AdminSocketRequest from the client.
                                if let Some(Ok(request)) = framed_rx.next().await {
                                    info!("Received request: {}", request);
                                    if let Ok(request) =
                                        serde_json::from_value::<AdminSocketRequest>(request)
                                    {
                                        let response = self.handle_request(request).await;
                                        let framed_tx =
                                            FramedWrite::new(conn_tx, BytesCodec::new());
                                        let mut framed_tx = SymmetricallyFramed::new(
                                            framed_tx,
                                            SymmetricalJson::<Value>::default(),
                                        );
                                        framed_tx
                                            .send(serde_json::to_value(&response).unwrap())
                                            .await;
                                    }
                                }
                            }
                            Some(Err(err)) => {
                                // Handle error here.
                                error!("Error accepting connection: {}", err);
                            }
                            None => {
                                break;
                            }
                        }
                    }
                }
                Listener::Unix(listener) => {
                    let mut listener = UnixListenerStream::new(listener);
                    loop {
                        match listener.next().await {
                            Some(Ok(mut conn)) => {
                                // Handle connection here.
                                // Wrap the socket in framed I/O using tokio-serde.
                                let (conn_rx, conn_tx) = conn.split();
                                let framed_rx = FramedRead::new(conn_rx, BytesCodec::new());
                                let mut framed_rx = SymmetricallyFramed::new(
                                    framed_rx,
                                    SymmetricalJson::<Value>::default(),
                                );
                                // Read an AdminSocketRequest from the client.
                                if let Some(Ok(request)) = framed_rx.next().await {
                                    info!("Received request: {}", request);
                                    if let Ok(request) =
                                        serde_json::from_value::<AdminSocketRequest>(request)
                                    {
                                        let response = self.handle_request(request).await;
                                        let framed_tx =
                                            FramedWrite::new(conn_tx, BytesCodec::new());
                                        let mut framed_tx = SymmetricallyFramed::new(
                                            framed_tx,
                                            SymmetricalJson::<Value>::default(),
                                        );
                                        framed_tx
                                            .send(serde_json::to_value(&response).unwrap())
                                            .await;
                                    }
                                }
                            }
                            Some(Err(err)) => {
                                // Handle error here.
                                error!("Error accepting connection: {}", err);
                            }
                            None => {
                                break;
                            }
                        }
                    }
                }
            }
        });
        Ok(())
    }

    async fn handle_request(&self, req: AdminSocketRequest) -> AdminSocketResponse {
        // Handle the request here.
        let status;
        let task = {
            let handlers = self.handlers.read().unwrap();
            if let Some(handler) = handlers.get(&req.request.to_lowercase()) {
                let func = &handler.func;
                let args = req.arguments.clone().unwrap_or(Value::Null);
                status = "success".into();
                func(args)
            } else {
                status = "error".into();
                Box::pin(async move { serde_json::to_value("Unknown command").unwrap() })
            }
        };

        let response = task.await;
        AdminSocketResponse {
            status,
            error: None,
            request: serde_json::to_value(req).unwrap(),
            response,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct GetSelfResponse {
    build_name: String,
    build_version: String,
    key: String,
    address: String,
    coords: Vec<u64>,
    subnet: String,
}

async fn get_self_handler(core: Arc<Core>) -> GetSelfResponse {
    let self_ = core.get_self().await;
    let subnet = core.subnet();
    GetSelfResponse {
        build_name: build_name().to_string(),
        build_version: build_version().to_string(),
        key: hex::encode(core.pconn.pconn.core.crypto.public_key.as_bytes()),
        address: core.address().to_string(),
        coords: self_.coords,
        subnet: subnet.to_string(),
    }
}

#[derive(Serialize, Deserialize)]
struct GetPeersResponse {
    peers: Vec<PeerEntry>,
}

#[derive(Serialize, Deserialize)]
struct PeerEntry {
    address: String,
    key: String,
    port: u64,
    priority: u64,
    coords: Vec<u64>,
    remote: String,
    bytes_recvd: u64,
    bytes_sent: u64,
    uptime: f64,
}

async fn get_peers_handler(core: Arc<Core>) -> GetPeersResponse {
    let peers = core.get_peers().await;
    let mut peer_entries = Vec::new();
    for peer in peers {
        let addr = addr_for_key(&peer.key).unwrap();
        let addr = address_to_ipv6(&addr);
        peer_entries.push(PeerEntry {
            address: addr.to_string(),
            key: hex::encode(peer.key.as_bytes()),
            port: peer.port as u64,
            priority: peer.priority as u64,
            coords: peer.coords,
            remote: peer.remote,
            bytes_recvd: peer.rx_bytes,
            bytes_sent: peer.tx_bytes,
            uptime: peer.uptime.as_secs_f64(),
        });
    }
    GetPeersResponse {
        peers: peer_entries,
    }
}

#[derive(Serialize, Deserialize)]
struct GetDHTResponse {
    dht: Vec<DHTEntry>,
}

#[derive(Serialize, Deserialize)]
struct DHTEntry {
    address: String,
    key: String,
    port: u64,
    rest: u64,
}

async fn get_dht_handler(core: Arc<Core>) -> GetDHTResponse {
    let dht = core.pconn.pconn.core.dhtree.get_dht().await;
    let mut dht_entries = Vec::new();
    for peer in dht {
        let addr = addr_for_key(&peer.key).unwrap();
        let addr = address_to_ipv6(&addr);
        dht_entries.push(DHTEntry {
            address: addr.to_string(),
            key: hex::encode(peer.key.as_bytes()),
            port: peer.port,
            rest: peer.rest,
        });
    }
    GetDHTResponse { dht: dht_entries }
}

#[derive(Serialize, Deserialize)]
struct GetPathsResponse {
    paths: Vec<PathEntry>,
}

#[derive(Serialize, Deserialize)]

struct PathEntry {
    address: String,
    key: String,
    path: Vec<u64>,
}

async fn get_paths_handler(core: Arc<Core>) -> GetPathsResponse {
    let paths = core.pconn.pconn.core.dhtree.get_paths().await;
    let mut path_entries = Vec::new();
    for peer in paths {
        let addr = addr_for_key(&peer.key).unwrap();
        let addr = address_to_ipv6(&addr);
        path_entries.push(PathEntry {
            address: addr.to_string(),
            key: hex::encode(peer.key.as_bytes()),
            path: peer.path,
        });
    }
    GetPathsResponse {
        paths: path_entries,
    }
}
