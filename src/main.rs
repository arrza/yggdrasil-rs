mod address;
mod config;
mod core;
mod defaults;
mod ipv6rwc;
mod tun;
mod version;

use crate::{
    address::{addr_for_key, subnet_for_key, to_ipv6},
    core::{Core, SetupOption},
    ipv6rwc::{KeyStore, ReadWriteCloser},
    tun::TunAdapter,
};
use clap::Parser;
use config::NodeConfig;
use ed25519_dalek::{PublicKey, SecretKey};
use hex::FromHex;
use ironwood_rs::{
    encrypted::packetconn::PacketConn,
    network::{
        crypto::PublicKeyBytes,
        wire::{Decode, Encode},
    },
    types::Addr,
};
use log::{debug, info, warn};
use nu_json::value::ToJson;
use std::{error::Error, io::Read, net::IpAddr, os::fd::AsRawFd, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    select,
    sync::mpsc,
};
use tokio_stream::wrappers::TcpListenerStream;
use tokio_tun::TunBuilder;
use version::VersionMetadata;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    peer: Option<String>,
    #[arg(short, long)]
    listen: Option<String>,
    #[arg(short, long)]
    key: String,
}

/// Rust implementation of yggdrasil
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct YggArgs {
    /// Print a new config to stdout
    #[arg(long)]
    genconf: bool,

    /// Read HJSON/JSON config from stdin
    #[arg(long)]
    useconf: bool,

    /// Read HJSON/JSON config from specified file path
    #[arg(long)]
    useconffile: Option<std::path::PathBuf>,

    /// Use in combination with either -useconf or -useconffile, outputs your configuration normalised
    #[arg(long)]
    normaliseconf: bool,

    /// Print configuration from -genconf or -normaliseconf as JSON instead of HJSON
    #[arg(long)]
    confjson: bool,

    /// Automatic mode (dynamic IP, peer with IPv6 neighbors)
    #[arg(long)]
    autoconf: bool,

    /// Prints the version of this build
    #[arg(long)]
    ver: bool,

    /// File path to log to, "syslog" or "stdout"
    #[arg(long, default_value = "stdout")]
    logto: String,

    /// Returns the IPv6 address as derived from the supplied configuration
    #[arg(long)]
    getaddr: bool,

    /// Returns the IPv6 subnet as derived from the supplied configuration
    #[arg(long)]
    getsnet: bool,

    /// Loglevel to enable
    #[arg(long, default_value = "info")]
    loglevel: String,
}

fn get_args() -> YggArgs {
    YggArgs::parse()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let args = get_args();
    run(args).await;
    return Ok(());
    // let args = Args::parse();
    // //console_subscriber::init();
    // //let client_key = "6113329ff0a8121a3697f77dfb6c88e98becbc01137fb3d90d62d394a40da61f";
    // let client_key = args.key;
    // let client_key = hex::decode(client_key)?;
    // let client_key = SecretKey::from_bytes(&client_key)?;
    // let client_pk: PublicKey = (&client_key).into();
    // println!("Client Pub Key: {}", hex::encode(client_pk.as_bytes()));
    // let (oob_handler_tx, mut oob_handler_rx) = mpsc::channel(10);
    // let (client_pconn, client_pconn_read) =
    //     PacketConn::new(&client_key, Some(oob_handler_tx)).await;
    // let addr = addr_for_key(&PublicKeyBytes::from(client_pk)).unwrap();
    // let addr = to_ipv6(&addr);

    // let tun = TunBuilder::new()
    //     .name("ygg-rs") // if name is empty, then it is set by kernel.
    //     .tap(false) // false (default): TUN, true: TAP.
    //     .packet_info(false) // false: IFF_NO_PI, default is true.
    //     .up() // or set it up manually using `sudo ip link set <tun-name> up`.
    //     .try_build()?; // or `.try_build_mq(queues)` for multi-queue support.

    // println!(
    //     "tun created, name: {}, fd: {}, addr: {}",
    //     tun.name(),
    //     tun.as_raw_fd(),
    //     addr
    // );
    // tokio::time::sleep(Duration::from_millis(100)).await;
    // std::process::Command::new("ip")
    //     .args(["addr", "add", &(addr.to_string() + "/7"), "dev", "ygg-rs"])
    //     .output()?;

    // let (mut tun_reader, mut tun_writer) = tokio::io::split(tun);

    // let client_task = async move {
    //     tokio::time::sleep(Duration::from_secs(1)).await;
    //     let mut conn;
    //     if let Some(peer) = args.peer {
    //         conn = TcpStream::connect(peer).await.unwrap();
    //     } else {
    //         let listener = TcpListener::bind(args.listen.unwrap()).await?;
    //         (conn, _) = listener.accept().await?;
    //     }

    //     let meta = VersionMetadata::get_base_metadata(client_pk.into());
    //     let mut meta_buf = Vec::new();
    //     meta.encode(&mut meta_buf);
    //     conn.write_all(&meta_buf).await.unwrap();
    //     conn.read_exact(&mut meta_buf).await.unwrap();
    //     let meta = VersionMetadata::decode(&meta_buf)?;
    //     if !meta.check() {
    //         return Err("Invalid version".into());
    //     }
    //     let server_pk = meta.key;
    //     client_pconn
    //         .pconn
    //         .handle_conn(server_pk.clone(), conn, 0)
    //         .await
    //         .unwrap();

    //     let (core, core_read) = Core::new(&client_key, client_pconn, client_pconn_read);
    //     let (mut key_store, mut key_store_read) = KeyStore::new(core, core_read);
    //     //println!("Client: {:?}", client_pconn)
    //     tokio::time::sleep(Duration::from_secs(5)).await;
    //     let dhtree = key_store.core.pconn.pconn.core.dhtree.clone();
    //     let mut key_store_oob = key_store.clone();
    //     let oob_task = async {
    //         while let Some((source, dest, msg)) = oob_handler_rx.recv().await {
    //             println!("OO: {} {} {}", source, dest, msg.len());
    //             key_store_oob
    //                 .oob_handler(source.into(), dest.into(), &msg)
    //                 .await;
    //         }
    //     };
    //     let rx_task = async {
    //         let mut buf = [0; 65536];
    //         while let Ok(rx_size) = key_store_read.read_pc(&mut buf).await {
    //             debug!("Received {} bytes ", rx_size);
    //             tun_writer.write_all(&buf[..rx_size]).await.unwrap();
    //         }
    //     };
    //     let tx_task = async {
    //         let mut buf_tun = [0; 65536];
    //         while let Ok(rx_size) = tun_reader.read(&mut buf_tun).await {
    //             debug!("Tun Received {} bytes ", rx_size);
    //             key_store
    //                 .write_pc(&buf_tun[..rx_size])
    //                 .await
    //                 .map_err(|e| println!("Error: {}", e));
    //         }
    //     };

    //     let dht_task = async {
    //         loop {
    //             tokio::time::sleep(Duration::from_secs(5)).await;
    //             let self_info = dhtree.get_self().await;
    //             println!("GetSelf: \n{:?}", self_info);
    //             let dht = dhtree.get_dht().await;
    //             println!("GetDHT: \n{:?}", dht);
    //         }
    //     };

    //     select! {
    //         _ = oob_task => {},
    //         _ = rx_task => {},
    //         _ = tx_task => {},
    //         _ = dht_task => {},
    //     }
    //     // loop {
    //     //     //tokio::time::sleep(Duration::from_secs(1)).await;
    //     //     // client_pconn
    //     //     //     .write_to(&payload, server_pk.clone())
    //     //     //     .await
    //     //     //     .unwrap();
    //     //     // let mut buf = [0; 65536];
    //     //     // if let Ok((rx_size, addr)) = core.read_from(&mut buf).await {
    //     //     //     println!("Received {} bytes from {}", rx_size, addr);
    //     //     // }

    //     //     select! {
    //     //         res = oob_handler_rx.recv() => {
    //     //             if let Some((source, dest, msg)) = res {

    //     //             }
    //     //         }
    //     //         res =  => {
    //     //             match res{
    //     //                 Ok(rx_size) =>  {

    //     //                 },
    //     //                 Err(e) => {
    //     //                     panic!("Received Err: {}  ", e);
    //     //                 }
    //     //             }
    //     //         }
    //     //         res =  => {
    //     //             match res {
    //     //                 Ok(rx_size) => {

    //     //                 }
    //     //                 Err(e) => {
    //     //                     panic!("Tun Received Err: {}  ", e);
    //     //                 }

    //     //             }

    //     //         }
    //     //         _ =  => {

    //     //         }
    //     //         // res = key_store.write_pc(&payload) => {
    //     //         //     if let Ok(tx_size) = res {
    //     //         //         println!("Sent {} bytes ", tx_size);
    //     //         //     }
    //     //         //     tokio::time::sleep(Duration::from_secs(1)).await;
    //     //         // }
    //     //     }
    //     // }
    //     Result::<(), Box<dyn Error>>::Ok(())
    // };

    // // let client_dh_handle = client_dhtree.handle();
    // // let client_dh_task = async move {
    // //     client_dhtree.init().await;
    // //     client_dhtree.handler().await
    // // };

    // // let check_dhtree_task = async move {
    // //     loop {
    // //         tokio::time::sleep(Duration::from_secs(4)).await;
    // //         println!("Client Dhtree");
    // //         client_dh_handle.debug().await;
    // //     }
    // // };
    // select! {
    //    _ = client_task => {},
    // //    _ = client_dh_task => {},
    //     //_ = check_dhtree_task => {},
    // }
    // Ok(())
}

fn read_config(useconf: bool, useconffile: &str, normaliseconf: bool) -> NodeConfig {
    // Use a configuration file. If -useconf, the configuration will be read
    // from stdin. If -useconffile, the configuration will be read from the
    // filesystem.
    let mut conf = Vec::new();
    if !useconffile.is_empty() {
        // Read the file from the filesystem
        conf = std::fs::read(useconffile).expect("Failed to read config file");
    } else if useconf {
        // Read the file from stdin
        std::io::stdin()
            .read_to_end(&mut conf)
            .expect("Failed to read config from stdin");
    }

    // Convert HJSON to JSON
    let hjson_string = String::from_utf8_lossy(&conf);
    //let json_string = nu_json::to_value(&hjson_string).expect("Failed to convert HJSON to JSON");

    // Deserialize the JSON into NodeConfig struct
    let cfg: NodeConfig =
        nu_json::from_str(&hjson_string).expect("Failed to deserialize JSON into NodeConfig");

    // Apply sane defaults
    // You can manually set the sane default values for the fields of NodeConfig here.

    cfg
}

fn do_genconf(is_json: bool) -> String {
    let cfg = defaults::generate_config();
    let result: String;

    if is_json {
        result = serde_json::to_string_pretty(&cfg).expect("JSON serialization error:");
    } else {
        result = nu_json::to_string(&cfg).expect("JSON serialization error:");
    }

    result
}

async fn run(args: YggArgs) -> Result<(), Box<dyn Error>> {
    // Create a new logger that logs output to stdout.
    warn!("Logging defaulting to stdout");

    let mut config = NodeConfig::default();
    match true {
        // Verbose, Version, NormaliseConf, GenConf
        _ if args.ver => {
            println!("Build name: {}", version::build_name());
            println!("Build version: {}", version::build_version());
            return Ok(());
        }
        _ if args.autoconf => config = defaults::generate_config(),
        _ if args.useconffile.is_some() || args.useconf => {
            config = read_config(
                args.useconf,
                &args
                    .useconffile
                    .map_or_else(|| "".to_string(), |v| v.to_string_lossy().to_string()),
                args.normaliseconf,
            );
            if args.normaliseconf {
                if args.confjson {
                    println!("{}", serde_json::to_string(&config).unwrap());
                } else {
                    println!("{}", nu_json::to_string(&config).unwrap());
                }
                return Ok(());
            }
        }
        _ if args.genconf => {
            println!("{}", do_genconf(args.confjson));
            return Ok(());
        }
        _ => {
            // No flags were provided, therefore print the list of flags to stdout.
            println!("Usage:");
            if args.getaddr || args.getsnet {
                println!(
                    "\nError: You need to specify some config data using -useconf or -useconffile."
                );
                return Ok(());
            }
        }
    }

    if args.getaddr {
        if let Some(key) = get_node_key(&config.private_key) {
            let addr = addr_for_key(&key).unwrap();
            let ip = IpAddr::V6(to_ipv6(&addr));
            println!("{}", ip);
        }
        return Ok(());
    }

    if args.getsnet {
        if let Some(key) = get_node_key(&config.private_key) {
            let snet = subnet_for_key(&key).unwrap();
            let mut addr = [0; 16];
            addr[..8].copy_from_slice(&snet);
            let ipnet = IpAddr::V6(to_ipv6(&addr));
            println!("{}", ipnet);
        }
        return Ok(());
    }
    let cfg = config;
    let core;
    let core_read;
    // Setup the Yggdrasil node itself.
    {
        let sk = hex::decode(cfg.private_key)?;
        let sk = SecretKey::from_bytes(&sk[..32])?;
        let mut options = vec![
            SetupOption::NodeInfo(cfg.node_info),
            SetupOption::NodeInfoPrivacy(cfg.node_info_privacy),
        ];

        for addr in cfg.listen {
            options.push(SetupOption::ListenAddress(addr))
        }
        for peer in cfg.peers {
            options.push(SetupOption::Peer(core::Peer {
                uri: peer,
                source_interface: None,
            }));
        }
        for (intf, peers) in cfg.interface_peers {
            for peer in peers {
                options.push(SetupOption::Peer(core::Peer {
                    uri: peer,
                    source_interface: Some(intf.clone()),
                }));
            }
        }

        for allowed in cfg.allowed_public_keys {
            let mut pk = PublicKeyBytes([0; 32]);
            hex::decode_to_slice(allowed, &mut pk.0)?;
            options.push(SetupOption::AllowedPublicKey(pk));
        }
        (core, core_read) = Core::new(&sk, options).await;
    }

    // Setup the admin socket.
    // Setup the multicast module.
    // Setup the TUN module.
    {
        let options = expotvec![
            SetupOption::InterfaceName(cfg.if_name),
            SetupOption::InterfaceMTU(cfg.if_mtu as u16),
        ];

        tokio::spawn(async move {
            let (rwc, rwc_read) = ReadWriteCloser::new(core, core_read);
            let tun = TunAdapter::new(&rwc, options).unwrap();
            tun.start(rwc, rwc_read).await;
        });
    }

    Ok(())
}

fn get_node_key(private_key: &str) -> Option<PublicKeyBytes> {
    if let Ok(pubkey) = <[u8; 32]>::from_hex(&private_key[..64]) {
        if let Ok(private_key) = ed25519_dalek::SecretKey::from_bytes(&pubkey) {
            return Some(PublicKeyBytes(pubkey));
        }
    }
    None
}
