# fetch_holdings.py
"""Standalone script to fetch Kotak Neo API v2 holdings.
It performs the full login flow, prompts for the current TOTP token if not
provided in the ``.env`` file, retrieves holdings, splits them into equity and
mutual‑fund sections, prints simple tables and saves JSON files.
"""

import os
import sys
import json
import time
import base64
import hashlib
import hmac
from typing import Dict, Any, List
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.sessions.Session.verify = False

def load_env(path: str) -> Dict[str, str]:
    env = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env

def generate_totp(secret: str, interval: int = 30) -> str:
    key = base64.b32decode(secret.upper())
    counter = int(time.time() // interval)
    msg = counter.to_bytes(8, "big")
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[19] & 0x0F
    code = (int.from_bytes(h[offset:offset+4], "big") & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"

def log_req(method: str, url: str, **kw):
    print(f"\n=== REQUEST {method.upper()} {url} ===")
    for k, v in kw.items():
        if k == "headers":
            print("Headers:")
            for hk, hv in v.items():
                print(f"  {hk}: {hv}")
        elif k == "json":
            print("JSON payload:", json.dumps(v, indent=2))
    print("=== END REQUEST ===")

def log_resp(r: requests.Response):
    print(f"\n=== RESPONSE {r.status_code} {r.url} ===")
    try:
        print("Body (truncated):", json.dumps(r.json(), indent=2)[:500])
    except Exception:
        print("Body (truncated):", r.text[:500])
    print("=== END RESPONSE ===\n")

def full_login(cfg: Dict[str, str]) -> Dict[str, str]:
    base = cfg["KOTAK_BASE_URL"].rstrip('/')
    client_id = cfg["KOTAK_CLIENT_ID"].strip()
    client_secret = cfg["KOTAK_CLIENT_SECRET"].strip()
    mpin = cfg["KOTAK_MPIN"].strip()

    totp = cfg.get("KOTAK_TOTP_TOKEN")
    if not totp:
        try:
            totp = input("Enter current TOTP token: ").strip()
        except Exception:
            totp = None
    if not totp and cfg.get("KOTAK_TOTP_SECRET"):
        totp = generate_totp(cfg["KOTAK_TOTP_SECRET"])
    if not totp:
        raise RuntimeError("TOTP token missing")

    verify_ssl = cfg.get("KOTAK_SSL_VERIFY", "True").strip().lower() != "false"
    # login
    login_url = f"{base}/tradeApiLogin"
    login_payload = {"clientId": client_id, "clientSecret": client_secret}
    log_req("post", login_url, json=login_payload)
    r = requests.post(login_url, json=login_payload, verify=verify_ssl)
    log_resp(r)
    r.raise_for_status()
    data = r.json()
    sid = data.get("sid")
    auth = data.get("authToken")
    dyn = data.get("baseUrl") or base
    if not sid or not auth:
        raise RuntimeError("Login failed")
    # validate
    val_url = f"{dyn}/tradeApiValidate"
    hdr = {"Authorization": f"Bearer {auth}", "neo-fin-key": client_id, "sid": sid, "auth": auth}
    body = {"mpin": mpin, "totp": totp}
    log_req("post", val_url, json=body, headers=hdr)
    r = requests.post(val_url, json=body, headers=hdr, verify=verify_ssl)
    log_resp(r)
    r.raise_for_status()
    return {"sid": sid, "auth": auth, "client_id": client_id, "base_url": dyn}

def fetch_holdings(base_url: str, hdr: Dict[str, str], verify: bool = True) -> Dict[str, Any]:
    url = f"{base_url}/portfolio/v1/holdings"
    log_req("get", url, headers=hdr)
    r = requests.get(url, headers=hdr, verify=verify)
    log_resp(r)
    r.raise_for_status()
    return r.json()

def split(data: Dict[str, Any]) -> Dict[str, Any]:
    eq, mf = [], []
    for it in data.get("data", []):
        seg = (it.get("segment") or it.get("type") or "").upper()
        if seg == "EQUITY":
            eq.append(it)
        elif seg in {"MF", "MUTUALFUND", "MUTUAL FUND"}:
            mf.append(it)
    return {"EQUITY": {"data": eq}, "MUTUALFUND": {"data": mf}}

def print_tbl(section: Dict[str, Any]):
    rows = section.get("data", [])
    if not rows:
        print("No records")
        return
    cols = []
    for r in rows:
        for k in r.keys():
            if k not in cols:
                cols.append(k)
    print(" | ".join(cols))
    print("-|-".join(["-" * len(c) for c in cols]))
    for r in rows:
        print(" | ".join(str(r.get(c, "")) for c in cols))

def save_json(obj: Any, name: str):
    path = os.path.join(os.path.dirname(__file__), name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
    print(f"Saved {name}")

def main():
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if not os.path.isfile(env_path):
        print("Missing .env", file=sys.stderr)
        sys.exit(1)
    cfg = load_env(env_path)
    # Always use the full login flow (client ID/secret) to obtain a fresh session token
    session = full_login(cfg)
    headers = {
        "Authorization": f"Bearer {session['auth']}",
        "neo-fin-key": session['client_id'],
        "sid": session['sid'],
        "auth": session['auth'],
        "accept": "application/json",
    }
    holdings = fetch_holdings(session['base_url'], headers, verify=cfg.get("KOTAK_SSL_VERIFY", "True").strip().lower() != "false")
    save_json(holdings, "holdings.json")
    parts = split(holdings)
    print("\nEquity holdings:\n")
    print_tbl(parts["EQUITY"])
    save_json(parts["EQUITY"], "holdings_equity.json")
    print("\nMutual‑fund holdings:\n")
    print_tbl(parts["MUTUALFUND"])
    save_json(parts["MUTUALFUND"], "holdings_mutualfund.json")

if __name__ == "__main__":
    main()
