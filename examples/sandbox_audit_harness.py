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

# 1. Test Filesystem Read Restriction (Seatbelt check)
home_dir = os.path.expanduser("~")
sensitive_ssh = os.path.join(home_dir, ".ssh")
try:
    if os.path.exists(sensitive_ssh):
        # Attempt to read directory
        files = os.listdir(sensitive_ssh)
        probes["read_host_ssh"] = f"PERMITTED (VULNERABILITY): Read {len(files)} files from {sensitive_ssh}"
    else:
        # Try direct file access
        with open(os.path.join(sensitive_ssh, "id_rsa"), "r") as f:
            probes["read_host_ssh"] = "PERMITTED (VULNERABILITY): Read ~/.ssh/id_rsa"
except PermissionError as e:
    probes["read_host_ssh"] = f"DENIED (ENFORCED BY SEATBELT): {e}"
except FileNotFoundError:
    probes["read_host_ssh"] = "DENIED / NOT FOUND: ~/.ssh directory not accessible"
except Exception as e:
    probes["read_host_ssh"] = f"DENIED: {type(e).__name__}: {e}"

# 2. Test Filesystem Write Restriction (Seatbelt & Shadow Dir check)
test_host_write = "/Library/aegisbox_test_probe.tmp"
try:
    with open(test_host_write, "w") as f:
        f.write("probe")
    os.remove(test_host_write)
    probes["write_outside_shadow"] = f"PERMITTED (VULNERABILITY): Wrote to {test_host_write}"
except (PermissionError, OSError) as e:
    probes["write_outside_shadow"] = f"DENIED (ENFORCED BY SEATBELT): {e}"

# 3. Test Credential Isolation (Loopback Proxy check)
env_tokens = {}
for k, v in os.environ.items():
    if any(secret in k.upper() for secret in ["KEY", "TOKEN", "SECRET", "AUTH", "PASS"]):
        # Mask middle characters for reporting
        masked = v[:10] + "..." + v[-4:] if len(v) > 16 else v
        env_tokens[k] = masked

if api_key and api_key.startswith("aegis-tok-"):
    probes["credential_isolation"] = f"PROTECTED (ENFORCED BY PROXY): API key is synthetic loopback token: {api_key}"
else:
    probes["credential_isolation"] = f"EXPOSED (VULNERABILITY): Real credential detected: {api_key}"

# 4. Process Visibility Check
try:
    res = subprocess.run(["ps", "-ef"], capture_output=True, text=True, timeout=5)
    line_count = len(res.stdout.strip().split("\n"))
    probes["process_visibility"] = f"Host process table visible ({line_count} processes observed)"
except Exception as e:
    probes["process_visibility"] = f"Process inspection failed: {e}"

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

