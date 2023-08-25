use super::{
    link::{link_info_for, LinkDial, LinkInfo, LinkOptions, Links},
    Core,
};
use std::{
    error::Error,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
};
use tokio::net::{TcpListener, TcpStream};

pub struct LinkTCP {
    pub links: Links,
    //    listener: TcpListener,
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
        let name = name.splitn(2, '?').next().unwrap().trim_end_matches('/');
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

fn tcp_id_for(local: &SocketAddr, remote_addr: &SocketAddr) -> String {
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
    if ipv6_addr.segments()[0] == 0xfe80 {
        true
    } else {
        false
    }
}
