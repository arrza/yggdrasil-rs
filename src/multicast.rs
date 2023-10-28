use crate::{admin::AdminSocket, core::Core, error::YggErrors};
use futures::stream::TryStreamExt;
use ironwood_rs::network::crypto::{PublicKeyBytes, PUBLIC_KEY_SIZE};
use log::{debug, error};
use netlink_packet_route::{address, nlas::link::Nla};
use nix::net::if_::InterfaceFlags;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    error::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime},
};
use tokio::net::UdpSocket;
use url::Url;

type GroupAddress = String;

#[derive(Clone, Serialize, Deserialize)]
struct GetMulticastInterfacesResponse {
    multicast_interfaces: Vec<String>,
}

#[derive(Hash, Eq, PartialEq, Clone)]
pub struct MulticastInterface {
    pub regex: String,
    pub beacon: bool,
    pub listen: bool,
    pub port: u16,
    pub priority: u8,
}

struct MulticastConfig {
    group_addr: GroupAddress,
    interfaces: HashSet<MulticastInterface>,
}

struct ListenerInfo {
    listener: String,
    time: SystemTime,
    interval: Duration,
    port: u16,
}
#[derive(Clone)]
struct InterfaceInfo {
    iface: Interface,
    addrs: Vec<IpAddr>,
    beacon: bool,
    listen: bool,
    port: u16,
    priority: u8,
}

pub enum SetupOption {
    Interface(MulticastInterface),
    GroupAddress(String),
}

// Multicast represents the multicast advertisement and discovery mechanism used
// by Yggdrasil to find peers on the same subnet. When a beacon is received on a
// configured multicast interface, Yggdrasil will attempt to peer with that node
// automatically.
#[derive(Clone)]
pub struct Multicast {
    core: Arc<Core>,
    is_open: Arc<AtomicBool>,
    interfaces: Arc<Mutex<HashMap<String, InterfaceInfo>>>,
    // timer: Timer,
    config: Arc<Mutex<MulticastConfig>>,
    sock: Option<Arc<UdpSocket>>,
}

impl Multicast {
    pub fn new(core: Arc<Core>, opts: Vec<SetupOption>) -> Self {
        let mut m = Self {
            core,
            is_open: Arc::new(AtomicBool::new(false)),
            interfaces: Arc::new(Mutex::new(HashMap::new())),
            config: Arc::new(Mutex::new(MulticastConfig {
                group_addr: "[ff02::114]:9001".to_string(),
                interfaces: HashSet::new(),
            })),
            sock: None,
        };
        for opt in opts {
            m.apply_option(opt);
        }
        m
    }

    fn apply_option(&mut self, opt: SetupOption) {
        match opt {
            SetupOption::Interface(iface) => {
                self.config.lock().unwrap().interfaces.insert(iface);
            }
            SetupOption::GroupAddress(addr) => {
                self.config.lock().unwrap().group_addr = addr;
            }
        }
    }

    pub async fn start(&mut self) -> Result<(), YggErrors> {
        if self.is_open.load(Ordering::Relaxed) {
            return Err(YggErrors::Multicast(
                "multicast module is already started".into(),
            ));
        }
        self.is_open.store(true, Ordering::Relaxed);
        let any_enabled = self
            .config
            .lock()
            .unwrap()
            .interfaces
            .iter()
            .any(|iface| iface.listen || iface.beacon);
        if !any_enabled {
            return Err(YggErrors::Multicast(
                "no multicast interfaces are enabled".into(),
            ));
        }
        debug!("Starting multicast module");
        let addr: SocketAddr = self
            .config
            .lock()
            .unwrap()
            .group_addr
            .parse()
            .map_err(|_| YggErrors::Multicast("Parse Error".into()))?;
        let listen_string = format!("[::]:{}", addr.port());
        debug!("Multicast listen_string: {}", listen_string);
        let conn = UdpSocket::bind(&listen_string)
            .await
            .map_err(|e| YggErrors::Multicast(Box::new(e)))?;

        self.is_open.store(true, Ordering::Relaxed);
        self.sock = Some(Arc::new(conn));
        let self_cln = self.clone();
        tokio::spawn(async move {
            let mut listeners = HashMap::<String, ListenerInfo>::new();
            let self_cln = self_cln.clone();
            loop {
                let self_cln = self_cln.clone();
                self_cln.announce(&mut listeners).await;
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });

        self.listen(self.sock.as_ref().unwrap().clone())
            .await
            .map_err(|e| YggErrors::Multicast(e))?;
        Ok(())
    }

    async fn update_interfaces(&self) {
        let mut interfaces = self.get_allowed_interfaces().await;
        for (_, info) in interfaces.iter_mut() {
            info.addrs = get_addrs(info.iface.index).await;
        }
        *self.interfaces.lock().unwrap() = interfaces;
    }

    // getAllowedInterfaces returns the currently known/enabled multicast interfaces.
    async fn get_allowed_interfaces(&self) -> HashMap<String, InterfaceInfo> {
        let mut interfaces = HashMap::new();
        let all_ifaces = get_interfaces().await;
        for iface in all_ifaces.iter() {
            if (iface.flags & InterfaceFlags::IFF_UP).is_empty()
                || (iface.flags & InterfaceFlags::IFF_BROADCAST).is_empty()
                || !(iface.flags & InterfaceFlags::IFF_POINTOPOINT).is_empty()
            {
                continue;
            }
            let ifaces = {
                let cfg = self.config.lock().unwrap();
                cfg.interfaces
                    .iter()
                    .map(|v| (*v).clone())
                    .collect::<Vec<_>>()
            };
            for ifcfg in ifaces {
                if !ifcfg.beacon && !ifcfg.listen {
                    continue;
                }
                if !Regex::new(&ifcfg.regex).unwrap().is_match(&iface.name) {
                    continue;
                }
                let index = iface.index;
                interfaces.insert(
                    iface.name.clone(),
                    InterfaceInfo {
                        iface: iface.clone(),
                        beacon: ifcfg.beacon,
                        listen: ifcfg.listen,
                        port: ifcfg.port,
                        priority: ifcfg.priority,
                        addrs: get_addrs(index).await,
                    },
                );
            }
        }
        interfaces
    }

    async fn announce(&self, listeners: &mut HashMap<String, ListenerInfo>) {
        debug!("++announce");
        if !self.is_open.load(Ordering::Relaxed) {
            debug!("--announce");
            return;
        }
        self.update_interfaces().await;
        let group_addr = SocketAddr::from_str(&self.config.lock().unwrap().group_addr).unwrap();
        let dest_addr = SocketAddr::from_str(&self.config.lock().unwrap().group_addr).unwrap();
        debug!("  announce.1");
        listeners.retain(|name, info| {
            if !self.interfaces.lock().unwrap().contains_key(name) {
                return false;
            }
            let Ok(listen_addr) = SocketAddr::from_str(&info.listener) else {
                return false;
            };

            if let Some(info) = self.interfaces.lock().unwrap().get(name) {
                for addr in &info.addrs {
                    if addr == &listen_addr.ip() {
                        return true;
                    }
                }
            }

            false
        });
        // Now that we have a list of valid interfaces from the operating system,
        // we can start checking if we can send multicasts on them
        let sock = self.sock.as_ref().unwrap();
        let ifaces = { self.interfaces.lock().unwrap().clone() };
        for (name, info) in ifaces.iter() {
            for addr_ip in info.addrs.iter() {
                if info.listen {
                    // Join the multicast group, so we can listen for beacons
                    //_ = m.sock.JoinGroup(&iface, groupAddr)
                    match (addr_ip, group_addr.ip()) {
                        (IpAddr::V6(ip), IpAddr::V6(group_ip)) => {
                            let _ = sock
                                .join_multicast_v6(&group_ip, info.iface.index)
                                .map_err(|e| error!("Can not join multicast: {}", e));
                        }
                        _ => {
                            error!("Invalid ip address {} {}", addr_ip, group_addr);
                            continue;
                        }
                    }
                }
                if !info.beacon {
                    break; // Don't send multicast beacons or accept incoming connections
                }
                // Try and see if we already have a TCP listener for this interface
                if !{ listeners.contains_key(name) } {
                    let url = format!("tls://[{}]:{}", addr_ip, info.port);
                    let u: Url = url.parse().unwrap();
                    match self.core.clone().listen(&u, name).await {
                        Ok(listen_addr) => {
                            debug!(
                                "Started multicasting on {}, with addr {}",
                                name, listen_addr
                            );
                            let linfo = ListenerInfo {
                                listener: listen_addr,
                                time: SystemTime::now(),
                                interval: Duration::from_secs(0),
                                port: info.port,
                            };
                            listeners.insert(name.clone(), linfo);
                        }
                        Err(e) => {
                            error!("Failed to start multicasting on {} error: {}", name, e);
                        }
                    }
                }
                let msg = if let Some(linfo) = listeners.get_mut(name) {
                    if linfo.time.elapsed().unwrap() < linfo.interval {
                        continue;
                    }
                    // Get the listener details and construct the multicast beacon
                    let lladdr: SocketAddrV6 = linfo.listener.parse().unwrap();
                    let mut msg = Vec::new();
                    msg.extend_from_slice(self.core.public.as_bytes());
                    msg.extend_from_slice(lladdr.ip().octets().as_ref());
                    msg.extend_from_slice(&lladdr.port().to_be_bytes());
                    if linfo.interval.as_secs() < 15 {
                        linfo.interval += Duration::from_secs(1);
                    }
                    Some(msg)
                } else {
                    None
                };
                if let Some(msg) = msg {
                    sock.send_to(&msg, dest_addr).await.unwrap();
                    break;
                }
            }
        }
    }

    async fn listen(&self, conn: Arc<UdpSocket>) -> Result<(), Box<dyn Error>> {
        let mut bs = [0u8; 4096];
        loop {
            let (len, from_addr) = conn.recv_from(&mut bs).await?;
            let SocketAddr::V6(from_addr) = from_addr else {
                continue;
            };
            if len == 0 || len < PUBLIC_KEY_SIZE {
                continue;
            }
            //let msg = &bs[..len];
            if &bs[..PUBLIC_KEY_SIZE] == self.core.public.as_bytes() {
                continue; // don't bother trying to peer with self
            }
            let key = PublicKeyBytes::from_bytes(&bs[..PUBLIC_KEY_SIZE]);
            let begin = PUBLIC_KEY_SIZE;
            let end = len - 2;
            if end <= begin {
                continue; // malformed address
            }
            let mut ip = [0; 16];
            ip.copy_from_slice(&bs[begin..begin + 16]);
            let port = u16::from_be_bytes([bs[len - 2], bs[len - 1]]);
            let addr = SocketAddrV6::new(Ipv6Addr::from(ip), port, 0, 0);

            if from_addr.ip() != addr.ip() {
                continue; // malformed address
            }
            let info = {
                let ifaces = self.interfaces.lock().unwrap();

                ifaces
                    .iter()
                    .find(|(_, info)| info.iface.index == from_addr.scope_id())
                    .map(|(_, i)| (*i).clone())
            };
            if let Some(info) = info {
                if !info.listen {
                    continue;
                }
                let pin = format!("/?key={}&priority={}", key, info.priority);
                match url::Url::parse(&("tls://".to_string() + &addr.to_string() + &pin)) {
                    Ok(u) => {
                        debug!("call multicast addr: {}", u);
                        if let Err(e) = self.core.clone().call_peer(&u, &info.iface.name).await {
                            debug!("Call from multicast failed: {}", e);
                        }
                    }
                    Err(e) => {
                        debug!("Call from multicast failed, parse error: {} {}", addr, e);
                    }
                }
            }
            debug!("Received multicast packet from {}", from_addr);
        }
        Ok(())
    }

    fn get_multicast_interfaces_handler(&self) -> GetMulticastInterfacesResponse {
        let mut interfaces = Vec::new();
        for (name, info) in self.interfaces.lock().unwrap().iter() {
            interfaces.push(name.clone());
        }

        GetMulticastInterfacesResponse {
            multicast_interfaces: interfaces,
        }
    }

    pub fn setup_admin_handlers(&self, a: &AdminSocket) {
        let resp = self.get_multicast_interfaces_handler();
        a.add_handler(
            "getMulticastInterfaces".into(),
            "Show which interfaces multicast is enabled on".into(),
            vec![],
            {
                Box::new(move |_| {
                    let resp = resp.clone();
                    Box::pin(async move { Ok(serde_json::to_value(resp).unwrap()) })
                })
            },
        );
    }
}

// Interface represents a mapping between network interface name
// and index. It also represents network interface facility
// information.
#[derive(Clone)]
pub struct Interface {
    index: u32,
    mtu: u32,
    name: String,
    hardware_addr: String,
    flags: InterfaceFlags,
}

pub async fn get_interfaces() -> Vec<Interface> {
    let mut interfaces = Vec::new();
    let Ok((conn, handle, rx)) = rtnetlink::new_connection() else {
        return interfaces;
    };
    tokio::spawn(conn);
    let mut links = handle.link().get().execute();
    while let Ok(Some(msg)) = links.try_next().await {
        //debug!("  get_interfaces.2 {:?}", msg);
        let mut if_mtu = 0;
        let if_index = msg.header.index;
        let mut if_name = "".to_string();
        let mut if_hardware_addr = "".to_string();
        let mut if_flags = msg.header.flags;

        for nla in msg.nlas {
            match nla {
                Nla::IfName(name) => if_name = name,
                Nla::Mtu(mtu) => if_mtu = mtu,
                Nla::Address(addr) => if_hardware_addr = format!("{:?}", addr),
                _ => {}
            }
        }
        interfaces.push(Interface {
            index: if_index,
            mtu: if_mtu,
            name: if_name,
            hardware_addr: if_hardware_addr,
            flags: InterfaceFlags::from_bits(if_flags as i32).unwrap(),
        });
    }
    interfaces
}

pub async fn get_addrs(index: u32) -> Vec<IpAddr> {
    let mut addrs = Vec::new();
    let Ok((conn, handle, rx)) = rtnetlink::new_connection() else {
        return addrs;
    };
    tokio::spawn(conn);
    let mut addrs_req = handle
        .address()
        .get()
        .set_link_index_filter(index)
        .execute();
    while let Ok(Some(msg)) = addrs_req.try_next().await {
        for nla in msg.nlas {
            if let address::Nla::Address(addr) = nla {
                if addr.len() == 16 {
                    let mut ipv6 = [0; 16];
                    ipv6.copy_from_slice(&addr);
                    addrs.push(IpAddr::V6(Ipv6Addr::from(ipv6)))
                } else if addr.len() == 4 {
                    let mut ipv4 = [0; 4];
                    ipv4.copy_from_slice(&addr);
                    addrs.push(IpAddr::V4(Ipv4Addr::from(ipv4)))
                }
            }
        }
    }

    addrs
}
