# holdings_fetcher.py
"""Fetch holdings from Kotak Neo API v2.

This script now supports two authentication modes:

1. **Full login flow** (client_id & client_secret are present) – identical to the original
2. **Direct token mode** – if ``KOTAK_ACCESS_TOKEN`` is defined in ``.env`` the script will skip the login steps and call the holdings endpoint using that token.

Both modes read configuration from ``.env`` and print a table of holdings, saving the raw JSON to ``holdings.json``.
"""

import os
import sys
import json
import time
import logging
import base64
import hashlib
import hmac

# Try to import NeoAPI SDK; if unavailable, fallback to manual requests
try:
    from neo_api_client import NeoAPI
except Exception:
    NeoAPI = None

# Existing imports
import requests
# Disable SSL verification warnings and enforce unverified connections globally (required for Kotak API with self‑signed certs)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# Monkey‑patch the default Session to skip verification for all requests (including SDK usage)
requests.sessions.Session.verify = False


# -------------------------------------------------
# .env loader (simple, no dependencies)
# -------------------------------------------------
def load_env(filepath: str) -> Dict[str, str]:
    env: Dict[str, str] = {}
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env

# -------------------------------------------------
# TOTP helper (RFC 6238, 30‑second step)
# -------------------------------------------------
def generate_totp(secret: str, interval: int = 30) -> str:
    key = base64.b32decode(secret.upper())
    msg = int(time.time() // interval)
    msg_bytes = msg.to_bytes(8, "big")
    h = hmac.new(key, msg_bytes, hashlib.sha1).digest()
    o = h[19] & 0x0F
    token = (int.from_bytes(h[o:o+4], "big") & 0x7fffffff) % 1_000_000
    return f"{token:06d}"

# -------------------------------------------------
# Logging helpers (stdout)
# -------------------------------------------------
def log_request(method: str, url: str, **kwargs) -> None:
    print(f"\n=== REQUEST {method.upper()} {url} ===")
    for k, v in kwargs.items():
        if k == "headers":
            print("Headers:")
            for hk, hv in v.items():
                print(f"  {hk}: {hv}")
        elif k == "json":
            print("JSON payload:", json.dumps(v, indent=2))
    print("=== END REQUEST ===")


def log_response(resp: requests.Response) -> None:
    print(f"\n=== RESPONSE {resp.status_code} {resp.url} ===")
    try:
        print("Body (truncated):", json.dumps(resp.json(), indent=2)[:500])
    except Exception:
        print("Body (truncated):", resp.text[:500])
    print("=== END RESPONSE ===\n")

# -------------------------------------------------
# Authentication – full login flow (client_id/secret)
# -------------------------------------------------
def full_login_flow(cfg: Dict[str, str]) -> Dict[str, str]:
    base_url = cfg["KOTAK_BASE_URL"].rstrip('/')
    client_id = cfg["KOTAK_CLIENT_ID"].strip()
    client_secret = cfg["KOTAK_CLIENT_SECRET"].strip()
    mpin = cfg["KOTAK_MPIN"]
    # ----- TOTP -----
    totp = cfg.get("KOTAK_TOTP_TOKEN")
    if not totp:
        # Prompt the user to input the current TOTP token
        try:
            totp = input("Enter current TOTP token: ").strip()
        except Exception:
            totp = None
    if not totp and cfg.get("KOTAK_TOTP_SECRET"):
        totp = generate_totp(cfg["KOTAK_TOTP_SECRET"])
    if not totp:
        raise RuntimeError("No TOTP token provided or generated for login")
    # ---- tradeApiLogin ----
    login_url = f"{base_url}/tradeApiLogin"
    login_payload = {"clientId": client_id, "clientSecret": client_secret}
    log_request("post", login_url, json=login_payload)
    # Respect SSL verification flag from config
    verify_ssl = cfg.get("KOTAK_SSL_VERIFY", "True").strip().lower() != "false"
    resp = requests.post(login_url, json=login_payload, verify=verify_ssl)
    log_response(resp)
    resp.raise_for_status()
    data = resp.json()
    sid = data.get("sid")
    auth_token = data.get("authToken")
    # Some implementations also return a dynamic base URL for subsequent calls
    dynamic_base = data.get("baseUrl") or base_url
    if not sid or not auth_token:
        raise RuntimeError("Login response missing sid or authToken")
    # ---- tradeApiValidate ----
    validate_url = f"{dynamic_base}/tradeApiValidate"
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "neo-fin-key": client_id,
        "sid": sid,
        "auth": auth_token,
    }
    body = {"mpin": mpin, "totp": totp}
    log_request("post", validate_url, json=body, headers=headers)
    resp = requests.post(validate_url, json=body, headers=headers, verify=verify_ssl)
    log_response(resp)
    resp.raise_for_status()
    return {"sid": sid, "auth": auth_token, "client_id": client_id, "base_url": dynamic_base}


# -------------------------------------------------
# Holdings fetch (common for both modes)
# -------------------------------------------------
def fetch_holdings(base_url: str, headers: Dict[str, str], verify: bool = True) -> Dict[str, Any]:
    """Fetch combined holdings from the Kotak Neo API.

    The endpoint does not accept a 'segment' query parameter; it returns the full
    portfolio, which we later split into equity and mutual‑fund sections.
    """
    holdings_url = f"{base_url}/portfolio/v1/holdings"
    log_request("get", holdings_url, headers=headers)
    resp = requests.get(holdings_url, headers=headers, verify=verify)
    log_response(resp)
    if resp.status_code == 401:
        raise PermissionError("Unauthorized – token may be expired")
    resp.raise_for_status()
    return resp.json()

# -------------------------------------------------
# Table printer
# -------------------------------------------------
def print_table(data: Dict[str, Any]) -> None:
    rows = data.get("data", [])
    if not rows:
        print("No holdings returned.")
        return
    # Determine column order (preserve first appearance)
    cols: List[str] = []
    for r in rows:
        for k in r.keys():
            if k not in cols:
                cols.append(k)
    # Header
    print(" | ".join(cols))
    print("-|-".join(["-" * len(c) for c in cols]))
    for r in rows:
        print(" | ".join(str(r.get(c, "")) for c in cols))

def save_raw(data: Dict[str, Any]) -> None:
    out_file = os.path.join(os.path.dirname(__file__), "holdings.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

# -------------------------------------------------
# Main driver
# -------------------------------------------------
# -------------------------------------------------
# Helper for direct token usage
# -------------------------------------------------
def fetch_holdings_direct(base_url: str, headers: Dict[str, str], verify: bool = True) -> Dict[str, Any]:
    """Fetch holdings when a bearer token is already available.
    The caller must provide the appropriate Authorization header.
    """
    holdings_url = f"{base_url}/portfolio/v1/holdings"
    # Ensure the accept header is present
    headers = {"accept": "application/json", **headers}
    log_request("get", holdings_url, headers=headers)
    resp = requests.get(holdings_url, headers=headers, verify=verify)
    log_response(resp)
    resp.raise_for_status()
    return resp.json()
def main() -> None:
    # Load configuration
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if not os.path.isfile(env_path):
        print(f"Missing .env file at {env_path}", file=sys.stderr)
        sys.exit(1)
    cfg = load_env(env_path)
    verify_ssl = cfg.get("KOTAK_SSL_VERIFY", "True").strip().lower() != "false"

    # Try SDK path first if SDK is available and ACCESS_TOKEN present
    if NeoAPI is not None and cfg.get("KOTAK_ACCESS_TOKEN"):
        try:
        # Use full login flow for authentication (SDK disabled due to SSL issues)
    combined_holdings = fetch_holdings_via_sdk(cfg)  # placeholder removed
    # Fallback to full login flow
    base_url = cfg.get("KOTAK_BASE_URL", "").rstrip('/')
    session = full_login_flow(cfg)
    headers = {
        "Authorization": f"Bearer {session['auth']}",
        "neo-fin-key": session['client_id'],
        "sid": session['sid'],
        "auth": session['auth'],
        "accept": "application/json",
    }
    combined_holdings = fetch_holdings(session['base_url'], headers, verify=verify_ssl)
    else:
        # Existing direct token flow (fallback)
        base_url = cfg.get("KOTAK_BASE_URL", "").rstrip('/')
        token = cfg.get("KOTAK_ACCESS_TOKEN", "").strip()
        if not token:
            print("KOTAK_ACCESS_TOKEN missing.", file=sys.stderr)
            sys.exit(1)
        headers = {"Authorization": token, "accept": "application/json", "neo-fin-key": cfg.get("KOTAK_UCC", "").strip()}
        combined_holdings = fetch_holdings(base_url, headers, verify=verify_ssl)
        base_url = cfg.get("KOTAK_BASE_URL", "").rstrip('/')
        token = cfg.get("KOTAK_ACCESS_TOKEN", "").strip()
        if not token:
            print("KOTAK_ACCESS_TOKEN missing.", file=sys.stderr)
            sys.exit(1)
        headers = {"Authorization": token, "accept": "application/json", "neo-fin-key": cfg.get("KOTAK_UCC", "").strip()}
        combined_holdings = fetch_holdings(base_url, headers, verify=verify_ssl)

def split_holdings(data: Dict[str, Any]) -> Dict[str, Any]:
    """Split combined holdings into equity and mutual fund sections.

    The API returns a list of holdings where each entry may contain a
    ``segment`` field indicating the type (e.g., ``EQUITY`` or ``MUTUALFUND``).
    This helper groups them accordingly.
    """
    equities = []
    mutuals = []
    for item in data.get("data", []):
        seg = item.get("segment") or item.get("type") or ""
        if seg.upper() == "EQUITY":
            equities.append(item)
        elif seg.upper() in {"MF", "MUTUALFUND", "MUTUAL FUND"}:
            mutuals.append(item)
    return {
        "EQUITY": {"data": equities},
        "MUTUALFUND": {"data": mutuals},
    }
    print("\nEquity (Stock) Holdings:\n")
    print_table(equity_holdings)
    equity_file = os.path.join(os.path.dirname(__file__), "holdings_equity.json")
    with open(equity_file, "w", encoding="utf-8") as f:
        json.dump(equity_holdings, f, indent=2)
    print(f"\nEquity holdings saved to {equity_file}\n")
    print("\nMutual Fund Holdings:\n")
    print_table(mf_holdings)
    mf_file = os.path.join(os.path.dirname(__file__), "holdings_mutualfund.json")
    with open(mf_file, "w", encoding="utf-8") as f:
        json.dump(mf_holdings, f, indent=2)
    print(f"\nMutual fund holdings saved to {mf_file}\n")

def fetch_holdings_via_sdk(cfg: Dict[str, str]) -> Dict[str, Any]:
    """Authenticate using the NeoAPI SDK and fetch holdings.

    This method uses the mobile number, UCC, TOTP token, and MPIN from the .env.
    The KOTAK_ACCESS_TOKEN is treated as the consumer key for the SDK.
    """
    if NeoAPI is None:
        raise RuntimeError("NeoAPI SDK not installed. Cannot use SDK authentication.")
    consumer_key = cfg.get("KOTAK_ACCESS_TOKEN")
    if not consumer_key:
        raise RuntimeError("KOTAK_ACCESS_TOKEN (consumer key) missing")
    client = NeoAPI(environment='prod', consumer_key=consumer_key, access_token=None, neo_fin_key=None)
    # Perform TOTP login
    client.totp_login(
        mobile_number=cfg.get("KOTAK_MOBILE_NUMBER"),
        ucc=cfg.get("KOTAK_UCC"),
        totp=cfg.get("KOTAK_TOTP_TOKEN")
    )
    # Validate MPIN to get trading token
    client.totp_validate(mpin=cfg.get("KOTAK_MPIN"))
    # Now fetch holdings
    holdings = client.holdings()
    return holdings



if __name__ == "__main__":
    main()
