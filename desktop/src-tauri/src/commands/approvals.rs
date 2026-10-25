use crate::ipc_client::PendingApproval;

#[tauri::command]
pub async fn submit_approval_decision(
    intercept_id: String,
    decision: String,
    scope: String,
) -> Result<bool, String> {
    // In production, delegates through IPC client to aegisboxd over local Unix socket / Named Pipe
    println!(
        "[Aegisbox Tauri] Submitted approval decision: id={}, decision={}, scope={}",
        intercept_id, decision, scope
    );
    Ok(true)
}

#[tauri::command]
pub async fn list_pending_approvals() -> Result<Vec<PendingApproval>, String> {
    // Returns active pending intercept queue
    Ok(vec![])
}
