use crate::core::link::link_options_for_listener;

use super::{
    link::{link_info_for, LinkDial, LinkInfo, LinkOptions, Links},
    Core,
};
use log::info;
use std::{
    error::Error,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
};
use tokio::net::{TcpSocket, TcpStream};
use tokio_stream::{wrappers::TcpListenerStream, StreamExt};

#[derive(Clone)]
pub struct LinkTCP {
    pub links: Links,
}

impl LinkTCP {
    pub async fn dial(
        &self,
        core: Arc<Core>,
        url: &url::Url,
        options: LinkOptions,
        sintf: &str,
    ) -> Result<(), Box<dyn Error>> {
        let addr = url.host_str().unwrap().to_string()
            + ":"
            + &url.port_or_known_default().unwrap().to_string();
        let addr = SocketAddr::from_str(&addr)?;
        let conn = TcpStream::connect(addr).await?;
        let info = link_info_for("tcp", sintf, &tcp_id_for(&conn.local_addr()?, &addr));

        if self.links.is_connected_to(&info) {
            return Ok(());
        }
        let name = url.to_string();
        let name = name.split('?').next().unwrap().trim_end_matches('/');
        let dial = LinkDial {
            url: url.clone(),
            sintf: sintf.to_string(),
        };

        self.handler(
            core,
            dial,
            name.to_string(),
            info.clone(),
            conn,
            options,
            false,
            false,
        )
        .await?;

        Ok(())
    }

    pub async fn listen(
        &self,
        core: Arc<Core>,
        url: &url::Url,
        sintf: &str,
    ) -> Result<String, Box<dyn Error>> {
        let addr = url.host_str().unwrap().to_string()
            + ":"
            + &url.port_or_known_default().unwrap().to_string();
        let addr: SocketAddr = SocketAddr::from_str(&addr)?;
        let tcp_socket = if addr.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        if !sintf.is_empty() {
            tcp_socket.bind_device(Some(sintf.as_bytes()))?;
        }
        tcp_socket.bind(addr)?;
        let addr = tcp_socket.local_addr()?;
        let listener = tcp_socket.listen(32)?;
        info!("TCP listener started on {}", listener.local_addr()?);
        let mut listener = TcpListenerStream::new(listener);
        let link = self.clone();
        let sintf = sintf.to_string();
        let url = url.clone();
        tokio::spawn(async move {
            while let Some(Ok(conn)) = listener.next().await {
                let info = link_info_for(
                    "tcp",
                    &sintf,
                    &tcp_id_for(
                        &conn.local_addr().map_err(|e| e.to_string())?,
                        &conn.peer_addr().map_err(|e| e.to_string())?,
                    ),
                );
                if link.links.is_connected_to(&info) {
                    continue;
                }
                let dial = LinkDial {
                    url: url.clone(),
                    sintf: sintf.to_string(),
                };
                link.handler(
                    core.clone(),
                    dial,
                    "tcp://".to_string()
                        + &conn.peer_addr().map_err(|e| e.to_string())?.to_string(),
                    info.clone(),
                    conn,
                    link_options_for_listener(&url),
                    true,
                    false,
                )
                .await;
            }
            info!(
                "TCP listener stopped on {}",
                listener.into_inner().local_addr().unwrap()
            );
            Result::<(), Box<String>>::Ok(())
        });
        Ok(addr.to_string())
    }

    async fn handler(
        &self,
        core: Arc<Core>,
        dial: LinkDial,
        name: String,
        info: LinkInfo,
        conn: TcpStream,
        options: LinkOptions,
        incoming: bool,
        force: bool,
    ) -> Result<(), Box<dyn Error>> {
        self.links
            .create(
                core, conn,     // connection
                dial,     // connection URL
                name,     // connection name
                info,     // connection info
                incoming, // not incoming
                force,    // not forced
                options,  // connection options
            )
            .await;

        Ok(())
    }
}

pub fn tcp_id_for(local: &SocketAddr, remote_addr: &SocketAddr) -> String {
    if let SocketAddr::V4(local_v4) = local {
        if let SocketAddr::V4(remote_v4) = remote_addr {
            if local_v4.ip() == remote_v4.ip() {
                // Nodes running on the same host — include both the IP and port.
                return remote_addr.to_string();
            }
        }
    } else if let SocketAddr::V6(local_v6) = local {
        if let SocketAddr::V6(remote_v6) = remote_addr {
            if local_v6.ip() == remote_v6.ip() {
                // Nodes running on the same host — include both the IP and port.
                return remote_addr.to_string();
            }
        }
    }

    if let IpAddr::V6(remote_ip_v6) = remote_addr.ip() {
        if is_unicast_link_local(&remote_ip_v6) {
            // Nodes discovered via multicast — include the IP only.
            return remote_ip_v6.to_string();
        }
    }

    // Nodes connected remotely — include both the IP and port.
    remote_addr.to_string()
}

fn is_unicast_link_local(ipv6_addr: &Ipv6Addr) -> bool {
    ipv6_addr.segments()[0] == 0xfe80
}
