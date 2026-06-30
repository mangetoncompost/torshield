use hmac::{Hmac, Mac, KeyInit};
use sha2::Sha256;
use security_framework::passwords::{set_generic_password, get_generic_password};

type HmacSha256 = Hmac<Sha256>;

use crate::helper::opsec_dir;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Config {
    pub exclude_us:  bool,
    pub exclude_gb:  bool,
    pub exclude_au:  bool,
    pub exclude_ca:  bool,
    pub exclude_nz:  bool,
    pub exclude_de:  bool,
    pub exclude_fr:  bool,
    pub rotate_mins: u32,
    pub mac_spoof:   bool,
    pub dns_leak:    bool,
    pub pf_firewall: bool,
    pub clear_logs:  bool,
    pub firefox:     bool,
    pub resist_fp:   bool,
    pub ua_spoof:    bool,
    pub lang_spoof:  bool,
    #[serde(default)]
    pub env_inject:  bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            exclude_us: true, exclude_gb: true, exclude_au: true,
            exclude_ca: true, exclude_nz: true, exclude_de: false, exclude_fr: false,
            rotate_mins: 0,
            mac_spoof: true, dns_leak: true, pf_firewall: false,
            clear_logs: true, firefox: true, resist_fp: true,
            ua_spoof: true, lang_spoof: true,
            env_inject: false,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct OpsecState {
    pub active:  bool,
    pub tor_ip:  Option<String>,
    pub real_ip: Option<String>,
    pub config:  Option<Config>,
}

pub type Shared = std::sync::Arc<std::sync::Mutex<(OpsecState, Config)>>;

const KC_SERVICE: &str = "TorShield";
const KC_ACCOUNT: &str = "config-hmac-key";

fn config_hmac_key() -> [u8; 32] {
    if let Ok(k) = get_generic_password(KC_SERVICE, KC_ACCOUNT) {
        if k.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&k);
            return arr;
        }
    }
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).expect("getrandom failed");
    set_generic_password(KC_SERVICE, KC_ACCOUNT, &key).ok();
    key
}

fn config_hmac(key: &[u8; 32], json: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(json.as_bytes());
    mac.finalize().into_bytes().iter().map(|b| format!("{:02x}", b)).collect()
}

impl Config {
    pub fn load() -> Self {
        let dir  = opsec_dir();
        let path = format!("{}/torshield.json", dir);
        let hmac_path = format!("{}/torshield.json.hmac", dir);

        let json = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(_) => return Self::default(),
        };

        let stored_hmac = std::fs::read_to_string(&hmac_path).unwrap_or_default();
        let stored_hmac = stored_hmac.trim();
        let key = config_hmac_key();
        let expected = config_hmac(&key, &json);
        if stored_hmac != expected {
            eprintln!("TorShield: config HMAC mismatch - resetting to defaults");
            let default = Self::default();
            default.save();
            return default;
        }

        serde_json::from_str(&json).unwrap_or_default()
    }

    pub fn save(&self) {
        let dir = opsec_dir();
        std::fs::create_dir_all(&dir).ok();
        let path = format!("{}/torshield.json", dir);
        let hmac_path = format!("{}/torshield.json.hmac", dir);
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let key = config_hmac_key();
            let mac = config_hmac(&key, &json);
            std::fs::write(&path, json).ok();
            std::fs::write(&hmac_path, mac).ok();
        }
    }

    pub fn excluded_nodes(&self) -> String {
        let mut v = vec![];
        if self.exclude_us { v.push("{us}"); }
        if self.exclude_gb { v.push("{gb}"); }
        if self.exclude_au { v.push("{au}"); }
        if self.exclude_ca { v.push("{ca}"); }
        if self.exclude_nz { v.push("{nz}"); }
        if self.exclude_de { v.push("{de}"); }
        if self.exclude_fr { v.push("{fr}"); }
        v.join(",")
    }
}
