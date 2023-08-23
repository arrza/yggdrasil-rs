mod defaults_linux;

use std::collections::HashMap;

use crate::config::{self, MulticastInterfaceConfig};

// PlatformDefaultParameters defines which parameters are expected by default
// for configuration on a specific platform.
#[derive(Debug)]
pub struct PlatformDefaultParameters {
    // Admin socket
    pub default_admin_listen: String,

    // Configuration (used for yggdrasilctl)
    pub default_config_file: String,

    // Multicast interfaces
    pub default_multicast_interfaces: Vec<MulticastInterfaceConfig>,

    // TUN
    pub maximum_if_mtu: u64,
    pub default_if_mtu: u64,
    pub default_if_name: String,
}

// impl Default for PlatformDefaultParameters {
//     fn default() -> Self {
//         PlatformDefaultParameters {
//             default_admin_listen: String::new(),
//             default_config_file: String::new(),
//             default_multicast_interfaces: Vec::new(),
//             maximum_if_mtu: 0,
//             default_if_mtu: 0,
//             default_if_name: String::new(),
//         }
//     }
// }

pub fn get_defaults() -> PlatformDefaultParameters {
    // Implement the logic to get defaults for your specific platform here
    // For example, you can use environment variables or configuration files.
    // Return a PlatformDefaultParameters struct with the default values.
    // You can also set the defaults using the Default trait for the struct.
    let mut defaults = PlatformDefaultParameters::default();
    if let Ok(default_config) = std::env::var("YGG_DEFAULT_CONFIG") {
        defaults.default_config_file = default_config;
    }
    if let Ok(default_admin_listen) = std::env::var("YGG_DEFAULT_ADMIN_LISTEN") {
        defaults.default_admin_listen = default_admin_listen;
    }
    // Implement other default values here

    defaults
}

// Generate default configuration and return a NodeConfig.
// This is used when outputting the -genconf parameter and also when using -autoconf.
pub fn generate_config() -> config::NodeConfig {
    // Get the defaults for the platform.
    let defaults = get_defaults();
    // Create a node configuration and populate it.
    let mut cfg = config::NodeConfig::default();
    cfg.new_keys();
    cfg.listen = Vec::new();
    cfg.admin_listen = defaults.default_admin_listen;
    cfg.peers = Vec::new();
    cfg.interface_peers = HashMap::new();
    cfg.allowed_public_keys = Vec::new();
    cfg.multicast_interfaces = defaults.default_multicast_interfaces;
    cfg.if_name = defaults.default_if_name;
    cfg.if_mtu = defaults.default_if_mtu;
    cfg.node_info_privacy = false;

    cfg
}
