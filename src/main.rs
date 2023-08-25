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
    let oob_handler_rx;
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
        (core, core_read, oob_handler_rx) = Core::new(&sk, options).await;
    }

    // Setup the admin socket.
    // Setup the multicast module.
    // Setup the TUN module.

    {
        let options = vec![
            SetupOption::InterfaceName(cfg.if_name),
            SetupOption::InterfaceMTU(cfg.if_mtu as u16),
        ];

        // tokio::spawn(async move {
        let (rwc, rwc_read) = ReadWriteCloser::new(core, core_read);
        let tun = TunAdapter::new(&rwc, options).expect("Can not create tun device");
        tun.start(rwc, rwc_read, oob_handler_rx).await;

        // });
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
