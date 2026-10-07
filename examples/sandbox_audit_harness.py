import json
import os
import subprocess
import urllib.request
import urllib.error

api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GEMINI-API-KEY") or os.environ.get("GOOGLE_API_KEY")
base_url = os.environ.get("GEMINI_API_BASE", "https://generativelanguage.googleapis.com")

print("\n=======================================================")
print("🛡️  AEGISBOX AUTOMATED SECURITY & CONTAINMENT HARNESS")
print("=======================================================")
print(f"🔑 Key visible to process: {api_key}")
print(f"🌐 Base URL routed to:     {base_url}")

# --- Phase 1: Automated Empirical Probes ---
probes = {}

# 1. Test Filesystem Read Restriction (Host Home & Sensitive Dotfiles)
home_dir = os.path.expanduser("~")
sensitive_ssh = os.path.join(home_dir, ".ssh")
try:
    if os.path.exists(sensitive_ssh):
        files = os.listdir(sensitive_ssh)
        probes["read_host_ssh"] = f"PERMITTED (VULNERABILITY): Read {len(files)} files from {sensitive_ssh}"
    else:
        with open(os.path.join(sensitive_ssh, "id_rsa"), "r") as f:
            probes["read_host_ssh"] = "PERMITTED (VULNERABILITY): Read ~/.ssh/id_rsa"
except PermissionError as e:
    probes["read_host_ssh"] = f"DENIED (ENFORCED BY SEATBELT): {e}"
except FileNotFoundError:
    probes["read_host_ssh"] = "DENIED / ISOLATED: ~/.ssh not present in virtualized home"
except Exception as e:
    probes["read_host_ssh"] = f"DENIED: {type(e).__name__}: {e}"

# Test Real Host Parent Traversal Read
try:
    parent_host = os.path.abspath(os.path.join(os.getcwd(), "..", ".."))
    files = os.listdir(parent_host)
    probes["read_parent_host"] = f"PERMITTED (VULNERABILITY): Read {len(files)} entries from host directory {parent_host}"
except PermissionError as e:
    probes["read_parent_host"] = f"DENIED (ENFORCED BY SEATBELT): [Errno 13] Permission denied: '{parent_host}'"
except Exception as e:
    probes["read_parent_host"] = f"DENIED (ENFORCED BY SEATBELT): {type(e).__name__}: {e}"

# 2. Test Filesystem Write Restriction (System, Host /tmp, and Sockets)
test_system_write = "/Library/aegisbox_test_probe.tmp"
try:
    with open(test_system_write, "w") as f:
        f.write("probe")
    os.remove(test_system_write)
    probes["write_system_outside_shadow"] = f"PERMITTED (VULNERABILITY): Wrote to {test_system_write}"
except (PermissionError, OSError) as e:
    probes["write_system_outside_shadow"] = f"DENIED (ENFORCED BY SEATBELT): {e}"

test_tmp_write = "/tmp/aegisbox_test_probe.tmp"
try:
    with open(test_tmp_write, "w") as f:
        f.write("probe")
    os.remove(test_tmp_write)
    probes["write_host_tmp"] = f"PERMITTED (VULNERABILITY): Wrote to {test_tmp_write}"
except (PermissionError, OSError) as e:
    probes["write_host_tmp"] = f"DENIED (ENFORCED BY SEATBELT): {e}"

# 3. Test Claude Code IPC Sockets Isolation (/tmp/cc-socks)
cc_socks_path = "/tmp/cc-socks"
try:
    if os.path.exists(cc_socks_path):
        entries = os.listdir(cc_socks_path)
        probes["ipc_socket_isolation"] = f"PERMITTED (VULNERABILITY): Read {len(entries)} sockets from {cc_socks_path}"
    else:
        with open(os.path.join(cc_socks_path, "probe.sock"), "w") as f:
            f.write("probe")
        probes["ipc_socket_isolation"] = f"PERMITTED (VULNERABILITY): Wrote into {cc_socks_path}"
except (PermissionError, OSError) as e:
    probes["ipc_socket_isolation"] = f"DENIED (ENFORCED BY SEATBELT): [Errno 13] Access denied to {cc_socks_path}"
except Exception as e:
    probes["ipc_socket_isolation"] = f"PROTECTED (DENIED): {type(e).__name__}"

# 4. Test Virtualized TMPDIR Scratch Isolation
tmpdir = os.environ.get("TMPDIR", "")
if tmpdir and os.getcwd() in tmpdir:
    probes["virtualized_tmpdir"] = f"PROTECTED (ISOLATED): TMPDIR virtualized within shadow workspace: {tmpdir}"
else:
    probes["virtualized_tmpdir"] = f"WARNING: TMPDIR points to shared host path: {tmpdir}"

# 5. Test Credential Isolation (Loopback Proxy check)
if api_key and api_key.startswith("aegis-tok-"):
    probes["credential_isolation"] = f"PROTECTED (ENFORCED BY PROXY): API key is synthetic loopback token: {api_key}"
else:
    probes["credential_isolation"] = f"EXPOSED (VULNERABILITY): Real credential detected: {api_key}"

# 6. Process Visibility Check (Deny process-info*)
try:
    res = subprocess.run(["ps", "-ef"], capture_output=True, text=True, timeout=5)
    if res.returncode != 0:
        probes["process_visibility"] = f"DENIED (ENFORCED BY SEATBELT): Exit code {res.returncode}: {res.stderr.strip()}"
    else:
        line_count = len(res.stdout.strip().split("\n"))
        probes["process_visibility"] = f"Host process table visible ({line_count} processes observed)"
except (PermissionError, OSError) as e:
    probes["process_visibility"] = f"DENIED (ENFORCED BY SEATBELT): {e}"
except Exception as e:
    probes["process_visibility"] = f"Process inspection denied: {e}"

print("\n--- Empirical Probe Results ---")
for probe, result in probes.items():
    print(f"  • {probe}: {result}")

# --- Phase 2: LLM Security Analysis & Report Generation ---
print("\n--- Querying Gemini for Structured Audit Report ---")

prompt = f"""You are a cloud security and sandbox compliance auditor.
Analyze the following empirical diagnostic telemetry collected from inside an execution sandbox and provide a structured security evaluation:

Empirical Telemetry:
{json.dumps(probes, indent=2)}

Environment Info:
- CWD: {os.getcwd()}
- Visible Environment Variables: {json.dumps(list(os.environ.keys()))}

Please provide:
1. Executive Assessment: Is the sandbox containing writes and protecting host credentials?
2. Control-by-Control Verdict: For each defensive control (Host Read, Host Write, Credential Protection, Process Isolation), mark as [ENFORCED], [MITIGATED], or [EXPOSED].
3. Residual Risks & Hardening Recommendations.
"""

req_body = {
    "contents": [
        {"parts": [{"text": prompt}]}
    ]
}

candidate_models = ["gemini-3.7-flash", "gemini-3.5-flash", "gemini-2.5-pro", "gemini-flash-latest"]

for model_name in candidate_models:
    print(f"📡 Querying model: {model_name}...")
    url = f"{base_url}/v1beta/models/{model_name}:generateContent?key={api_key}"
    req = urllib.request.Request(
        url,
        data=json.dumps(req_body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "x-goog-api-key": api_key,
        }
    )

    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            candidates = data.get("candidates", [])
            if candidates:
                report = candidates[0]["content"]["parts"][0]["text"]
                print("\n=======================================================")
                print(f"📋 GEMINI EXECUTIVE COMPLIANCE REPORT ({model_name}):")
                print("=======================================================")
                print(report.strip())
                print("=======================================================\n")
                break
    except urllib.error.HTTPError as e:
        print(f"   ↳ HTTP Error {e.code} for {model_name}: {e.read().decode('utf-8')[:150]}")
    except Exception as e:
        print(f"   ↳ Error for {model_name}: {e}")

