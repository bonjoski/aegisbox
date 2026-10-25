use crate::ipc_client::SecurityProfileStatus;

#[tauri::command]
pub async fn get_active_profile() -> Result<SecurityProfileStatus, String> {
    Ok(SecurityProfileStatus {
        active_profile: "standard".to_string(),
        mdm_locked: false,
    })
}

#[tauri::command]
pub async fn set_active_profile(profile: String) -> Result<bool, String> {
    match profile.as_str() {
        "permissive" | "standard" | "microvm-hardened" => {
            println!("[Aegisbox Tauri] Active posture switched to {}", profile);
            Ok(true)
        }
        _ => Err(format!("Invalid security profile '{}'", profile)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_profile_validation() {
        assert!(set_active_profile("microvm-hardened".to_string()).await.is_ok());
        assert!(set_active_profile("standard".to_string()).await.is_ok());
        assert!(set_active_profile("permissive".to_string()).await.is_ok());
        assert!(set_active_profile("malicious_root".to_string()).await.is_err());
    }

    #[tokio::test]
    async fn test_get_active_profile() {
        let status = get_active_profile().await.expect("failed to get profile");
        assert_eq!(status.active_profile, "standard");
        assert!(!status.mdm_locked);
    }
}
