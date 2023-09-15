use super::defaults;
use crate::{
    address::{address_to_ipv6, Address, Subnet},
    admin::AdminSocket,
    core::SetupOption,
    error::YggErrors,
    ipv6rwc::{ReadWriteCloser, ReadWriteCloserRead},
};
use ironwood_rs::network::packetconn::OobHandlerRx;
use log::{debug, error};
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    f32::consts::E,
    sync::{
        atomic::{AtomicBool, AtomicU16, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    select,
};
use tokio_tun::{Tun, TunBuilder};

type MTU = u16;

#[derive(Serialize, Deserialize)]
struct GetTunResponse {
    enabled: bool,
    name: String,
    mtu: u64,
}

struct TunAdapterConfig {
    name: String,
    mtu: u16,
}
pub struct TunAdapter {
    addr: Address,
    subnet: Subnet,
    mtu: Arc<AtomicU16>,
    iface: Tun,
    is_open: bool,
    is_enabled: Arc<AtomicBool>,
    config: TunAdapterConfig,
}

// Gets the maximum supported MTU for the platform based on the defaults in
// defaults.GetDefaults().
pub fn get_supported_mtu(mtu: u16) -> u16 {
    if mtu < 1280 {
        return 1280;
    }
    if mtu > maximum_mtu() {
        return maximum_mtu();
    }
    mtu
}

// DefaultName gets the default TUN interface name for your platform.
fn default_name() -> String {
    defaults::get_defaults().default_if_name
}

// DefaultMTU gets the default TUN interface MTU for your platform. This can
// be as high as MaximumMTU(), depending on platform, but is never lower than 1280.
fn default_mtu() -> u16 {
    defaults::get_defaults().default_if_mtu as u16
}

// MaximumMTU returns the maximum supported TUN interface MTU for your
// platform. This can be as high as 65535, depending on platform, but is never
// lower than 1280.
fn maximum_mtu() -> u16 {
    defaults::get_defaults().maximum_if_mtu as u16
}

impl TunAdapter {
    pub fn mtu(&self) -> u16 {
        get_supported_mtu(self.mtu.load(Ordering::Relaxed))
    }

    pub fn new(rwc: &ReadWriteCloser, opts: Vec<SetupOption>) -> Result<Self, Box<dyn Error>> {
        let mut config = TunAdapterConfig {
            name: "".to_string(),
            mtu: 0,
        };
        for c in opts {
            match c {
                SetupOption::InterfaceName(name) => config.name = name,
                SetupOption::InterfaceMTU(mtu) => config.mtu = mtu,
                _ => {}
            }
        }
        let iface = TunBuilder::new()
            .name("ygg-rs") // if name is empty, then it is set by kernel.
            .tap(false) // false (default): TUN, true: TAP.
            .packet_info(false) // false: IFF_NO_PI, default is true.
            .up() // or set it up manually using `sudo ip link set <tun-name> up`.
            .try_build()?; // or `.try_build_mq(queues)` for multi-queue support.

        Ok(TunAdapter {
            addr: rwc.address(),
            subnet: rwc.subnet(),
            mtu: Arc::new(AtomicU16::new(if config.mtu > rwc.max_mtu() {
                rwc.max_mtu()
            } else {
                config.mtu
            })),
            iface,
            is_open: false,
            is_enabled: Arc::new(AtomicBool::new(false)),
            config,
        })
    }

    pub async fn start(
        mut self,
        mut rwc: ReadWriteCloser,
        mut rwc_read: ReadWriteCloserRead,
        mut oob_handler_rx: OobHandlerRx,
    ) -> Result<(), String> {
        if self.is_open {
            return Err("TUN module is already started".into());
        }
        if self.config.name == "none" || self.config.name == "dummy" {
            debug!("Not starting TUN as ifname is none or dummy");
            self.is_enabled.store(false, Ordering::Relaxed);
            return Err("TUN module is disabled".into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        std::process::Command::new("ip")
            .args([
                "addr",
                "add",
                &(address_to_ipv6(&self.addr).to_string() + "/7"),
                "dev",
                "ygg-rs",
            ])
            .output()
            .map_err(|e| e.to_string())?;

        std::process::Command::new("ip")
            .args(["link", "set", "dev", "ygg-rs", "mtu", "53000"])
            .output()
            .map_err(|e| e.to_string())?;
        let mtu = 53000;
        self.mtu.store(mtu, Ordering::Relaxed);
        rwc.set_mtu(mtu);
        rwc_read.set_mtu(mtu);

        let key_store_oob = rwc.key_store.clone();
        let oob_task = async {
            while let Some((source, dest, msg)) = oob_handler_rx.recv().await {
                println!("OO: {} {} {}", source, dest, msg.len());
                key_store_oob.oob_handler(source, dest, &msg).await;
            }
        };

        let (mut tun_reader, mut tun_writer) = tokio::io::split(self.iface);
        let rx_task = async {
            let mut buf = [0; 65536];
            while let Ok(rx_size) = rwc_read.read(&mut buf).await {
                debug!("Received {} bytes ", rx_size);
                tun_writer.write_all(&buf[..rx_size]).await.unwrap();
            }
        };
        let tx_task = async {
            let mut buf_tun = [0; 65536];
            while let Ok(rx_size) = tun_reader.read(&mut buf_tun).await {
                debug!("Tun Received {} bytes ", rx_size);
                let Err(e) = rwc.write(&buf_tun[..rx_size]).await else {
                    continue;
                };
                error!("Error sending tun packet: {}", e);
                if let YggErrors::SendError(_) = e {
                    break;
                }
            }
        };
        self.is_open = true;
        self.is_enabled.store(true, Ordering::Relaxed);
        select! {
            _ = rx_task => {},
            _ = tx_task => {},
            _ = oob_task => {},
        }
        Ok(())
    }

    pub fn setup_admin_handlers(&self, a: &AdminSocket) {
        let a = a.clone();
        let is_enabled = self.is_enabled.clone();
        let mtu = self.mtu.clone();
        let name = self.config.name.clone();
        a.add_handler(
            "getTun".into(),
            "Show information about the node's TUN interface".into(),
            vec![],
            {
                Box::new(move |_| {
                    let is_enabled = is_enabled.clone();
                    let mtu = mtu.clone();
                    let name = name.clone();
                    Box::pin(async move {
                        let resp = GetTunResponse {
                            enabled: is_enabled.load(Ordering::Relaxed),
                            name,
                            mtu: mtu.load(Ordering::Relaxed) as u64,
                        };
                        Ok(serde_json::to_value(resp).unwrap())
                    })
                })
            },
        );
    }
}
