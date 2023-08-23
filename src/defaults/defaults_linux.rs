use super::PlatformDefaultParameters;
use crate::config::MulticastInterfaceConfig;

impl Default for PlatformDefaultParameters {
    fn default() -> PlatformDefaultParameters {
        PlatformDefaultParameters {
            // Admin
            default_admin_listen: "tcp://[::1]:9001".to_string(),

            // Configuration (used for yggdrasilctl)
            default_config_file: "/etc/yggdrasil.conf".to_string(),

            // Multicast interfaces
            default_multicast_interfaces: vec![MulticastInterfaceConfig {
                regex: ".*".to_string(),
                beacon: true,
                listen: true,
                port: 0,
                priority: 0,
            }],

            // TUN
            maximum_if_mtu: 65535,
            default_if_mtu: 65535,
            default_if_name: "auto".to_string(),
        }
    }
}
