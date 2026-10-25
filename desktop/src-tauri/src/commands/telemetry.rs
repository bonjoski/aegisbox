use std::path::PathBuf;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetrySnapshot {
    pub cpu_percent: f64,
    pub memory_rss_bytes: u64,
    pub active_vms: usize,
    pub canary_clean: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveLogItem {
    pub id: i64,
    #[serde(rename = "timestampNs")]
    pub timestamp_ns: i64,
    #[serde(rename = "vmId")]
    pub vm_id: String,
    pub category: String,
    pub text: String,
    #[serde(rename = "canaryTriggered")]
    pub canary_triggered: Option<bool>,
    #[serde(rename = "canaryTargetIp")]
    pub canary_target_ip: Option<String>,
}

#[derive(Deserialize)]
struct RawEvent {
    timestamp_ns: i64,
    vm_id: String,
    category: String,
    message: String,
    canary_triggered: Option<bool>,
    canary_target_ip: Option<String>,
}

fn get_events_path() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        let p = PathBuf::from(&home).join(".aegisbox").join("events.jsonl");
        if p.exists() {
            return p;
        }
    }
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        let p = PathBuf::from(runtime_dir).join("aegisbox").join("events.jsonl");
        if p.exists() {
            return p;
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".aegisbox").join("events.jsonl")
    } else {
        PathBuf::from("/tmp/aegisbox-events.jsonl")
    }
}

#[tauri::command]
pub async fn check_daemon_status() -> Result<bool, String> {
    Ok(crate::ipc_client::DaemonClient::new().is_alive())
}

#[tauri::command]
pub async fn get_telemetry_snapshot() -> Result<TelemetrySnapshot, String> {
    Ok(TelemetrySnapshot {
        cpu_percent: 1.2,
        memory_rss_bytes: 42 * 1024 * 1024,
        active_vms: 0,
        canary_clean: true,
    })
}

#[allow(non_snake_case)]
#[tauri::command]
pub async fn get_live_events(
    since_ns: Option<i64>,
    sinceNs: Option<i64>,
) -> Result<Vec<LiveLogItem>, String> {
    let cutoff = since_ns.or(sinceNs).unwrap_or(0);
    let path = get_events_path();
    if !path.exists() {
        return Ok(vec![]);
    }

    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) => return Err(e.to_string()),
    };

    let reader = std::io::BufReader::new(file);
    use std::io::BufRead;

    let mut events = Vec::new();
    let mut line_id = 0i64;

    for line in reader.lines() {
        line_id += 1;
        if let Ok(l) = line {
            if l.trim().is_empty() {
                continue;
            }
            if let Ok(raw) = serde_json::from_str::<RawEvent>(&l) {
                if raw.timestamp_ns > cutoff {
                    events.push(LiveLogItem {
                        id: line_id,
                        timestamp_ns: raw.timestamp_ns,
                        vm_id: raw.vm_id,
                        category: raw.category,
                        text: raw.message,
                        canary_triggered: raw.canary_triggered,
                        canary_target_ip: raw.canary_target_ip,
                    });
                }
            }
        }
    }

    if events.len() > 500 {
        events = events.split_off(events.len() - 500);
    }

    Ok(events)
}
