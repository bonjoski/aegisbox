use std::path::PathBuf;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingApproval {
    #[serde(rename = "interceptId")]
    pub intercept_id: String,
    #[serde(rename = "vmId")]
    pub vm_id: String,
    #[serde(rename = "toolName")]
    pub tool_name: String,
    #[serde(rename = "toolArgsJson")]
    pub tool_args_json: String,
    pub severity: String,
    pub reason: String,
    #[serde(rename = "timestampNs")]
    pub timestamp_ns: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityProfileStatus {
    #[serde(rename = "activeProfile")]
    pub active_profile: String,
    #[serde(rename = "mdmLocked")]
    pub mdm_locked: bool,
}

pub fn default_socket_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(r"\\.\pipe\aegisboxd")
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
            PathBuf::from(runtime_dir).join("aegisbox").join("aegisboxd.sock")
        } else if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(".aegisbox").join("aegisboxd.sock")
        } else {
            PathBuf::from("/tmp/aegisbox-daemon.sock")
        }
    }
}

pub struct DaemonClient {
    pub socket_path: PathBuf,
}

impl DaemonClient {
    pub fn new() -> Self {
        Self {
            socket_path: default_socket_path(),
        }
    }

    pub fn is_alive(&self) -> bool {
        #[cfg(not(target_os = "windows"))]
        {
            self.socket_path.exists()
        }
        #[cfg(target_os = "windows")]
        {
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_socket_path() {
        let path = default_socket_path();
        let path_str = path.to_string_lossy();
        assert!(path_str.contains("aegisboxd"), "expected aegisboxd in socket path, got: {}", path_str);
    }
}
