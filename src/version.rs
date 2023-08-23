use ironwood_rs::network::{
    crypto::{PublicKeyBytes, PUBLIC_KEY_SIZE},
    wire::{Decode, Encode, WireDecodeError},
};

#[derive(Debug, Clone)]
pub struct VersionMetadata {
    meta: [u8; 4],
    pub ver: u8,
    pub minor_ver: u8,
    pub key: PublicKeyBytes,
}

impl VersionMetadata {
    pub fn get_base_metadata(key: PublicKeyBytes) -> VersionMetadata {
        VersionMetadata {
            meta: *b"meta",
            ver: 0,
            minor_ver: 4,
            key,
        }
    }

    pub fn get_meta_length() -> usize {
        4 + 1 + 1 + PUBLIC_KEY_SIZE
    }

    pub fn check(&self) -> bool {
        let base = VersionMetadata::get_base_metadata(PublicKeyBytes([0; PUBLIC_KEY_SIZE]));
        self.meta == base.meta && self.ver == base.ver && self.minor_ver == base.minor_ver
    }
}

impl Encode for VersionMetadata {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.meta);
        out.push(self.ver);
        out.push(self.minor_ver);
        out.extend_from_slice(self.key.as_bytes());

        if out.len() != Self::get_meta_length() {
            panic!("Inconsistent metadata length");
        }
    }
}

impl Decode for VersionMetadata {
    fn decode(data: &[u8]) -> Result<Self, WireDecodeError> {
        if data.len() != Self::get_meta_length() {
            return Err(WireDecodeError);
        }

        let mut meta = [0u8; 4];
        let (meta_data, rest) = data.split_at(4);
        meta.copy_from_slice(meta_data);

        let (ver_data, rest) = rest.split_at(1);
        let ver = ver_data[0];

        let (minor_ver_data, rest) = rest.split_at(1);
        let minor_ver = minor_ver_data[0];

        let mut key_data = [0u8; PUBLIC_KEY_SIZE];
        key_data.copy_from_slice(rest);
        let key = PublicKeyBytes(key_data);

        Ok(VersionMetadata {
            meta,
            ver,
            minor_ver,
            key,
        })
    }
}

// Define static variables for build name and build version
static mut BUILD_NAME: Option<String> = None;
static mut BUILD_VERSION: Option<String> = None;

// Set the build name and build version. This function should be called
// during initialization to inject the values if built from git.
pub fn set_build_info(name: &str, version: &str) {
    unsafe {
        BUILD_NAME = Some(name.to_string());
        BUILD_VERSION = Some(version.to_string());
    }
}

// Get the current build name. This function returns "unknown" if the build
// name was not set during initialization.
pub fn build_name() -> &'static str {
    unsafe {
        if BUILD_NAME.is_some() {
            BUILD_NAME.as_ref().unwrap()
        } else {
            "unknown"
        }
    }
}

// Get the current build version. This function returns "unknown" if the
// build version was not set during initialization.
pub fn build_version() -> &'static str {
    unsafe {
        if BUILD_VERSION.is_some() {
            BUILD_VERSION.as_ref().unwrap()
        } else {
            "unknown"
        }
    }
}
