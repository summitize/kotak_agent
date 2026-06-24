import os
import sys
import time
import hmac
import hashlib
import struct
import base64
import requests
import json
import logging

# Simple dotenv parser to run locally without python-dotenv package dependency
def load_dotenv(dotenv_path=".env"):
    if os.path.exists(dotenv_path):
        with open(dotenv_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                # Strip spaces and optional quotes
                key = key.strip()
                val = val.strip().strip("'").strip('"')
                os.environ[key] = val

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("kotak_neo.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("KotakNeoClient")

def generate_totp(secret):
    """
    Generates a 6-digit TOTP token using only Python standard libraries (RFC 6238).
    """
    secret = secret.replace(" ", "")
    # Add base32 padding if missing
    missing_padding = len(secret) % 8
    if missing_padding:
        secret += '=' * (8 - missing_padding)
    try:
        key = base64.b32decode(secret, casefold=True)
    except Exception as e:
        raise ValueError(f"Invalid Base32 secret key format: {e}")
        
    counter = int(time.time() // 30)
    msg = struct.pack(">Q", counter)
    hs = hmac.new(key, msg, hashlib.sha1).digest()
    offset = hs[-1] & 0x0f
    bin_code = struct.unpack(">I", hs[offset:offset+4])[0] & 0x7fffffff
    totp = bin_code % 1000000
    return f"{totp:06d}"

def mask_sensitive_headers(headers):
    """
    Masks authorization and session identifiers for secure logging.
    """
    masked = {}
    for k, v in headers.items():
        k_lower = k.lower()
        if k_lower in ["authorization", "auth", "sid"]:
            val_str = str(v)
            if len(val_str) > 8:
                masked[k] = f"{val_str[:4]}...{val_str[-4:]}"
            else:
                masked[k] = "********"
        else:
            masked[k] = v
    return masked

def mask_sensitive_payload(payload):
    """
    Masks credentials inside JSON payloads.
    """
    if not payload:
        return payload
    if isinstance(payload, dict):
        masked = {}
        for k, v in payload.items():
            k_lower = k.lower()
            if k_lower in ["mpin", "totp", "secret", "password", "token", "auth", "sid"]:
                masked[k] = "********"
            elif isinstance(v, (dict, list)):
                masked[k] = mask_sensitive_payload(v)
            else:
                masked[k] = v
        return masked
    elif isinstance(payload, list):
        return [mask_sensitive_payload(item) for item in payload]
    return payload

class KotakNeoClient:
    def __init__(self, dotenv_path=".env"):
        load_dotenv(dotenv_path)
        self._validate_env()
        
        self.access_token = os.environ.get("KOTAK_ACCESS_TOKEN", "").strip()
        self.mobile_number = os.environ.get("KOTAK_MOBILE_NUMBER", "").strip()
        self.ucc = os.environ.get("KOTAK_UCC", "").strip()
        self.mpin = os.environ.get("KOTAK_MPIN", "").strip()
        self.totp_token = os.environ.get("KOTAK_TOTP_TOKEN", "").strip()
        self.totp_secret = os.environ.get("KOTAK_TOTP_SECRET", "").strip()
        
        # SSL Verification option (defaults to True)
        ssl_verify_str = os.environ.get("KOTAK_SSL_VERIFY", "True").strip().lower()
        self.ssl_verify = ssl_verify_str not in ["false", "0", "no"]
        
        if not self.ssl_verify:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logger.warning("SSL verification is disabled (verify=False). Request warnings are suppressed.")
            
        self.session_token = None
        self.session_sid = None
        self.base_url = None
        
        self.session = requests.Session()

    def _validate_env(self):
        """
        Validates the configuration environment and terminates the process if invalid.
        """
        missing = []
        if not os.environ.get("KOTAK_ACCESS_TOKEN", "").strip():
            missing.append("KOTAK_ACCESS_TOKEN")
        if not os.environ.get("KOTAK_MOBILE_NUMBER", "").strip():
            missing.append("KOTAK_MOBILE_NUMBER")
        if not os.environ.get("KOTAK_UCC", "").strip():
            missing.append("KOTAK_UCC")
        if not os.environ.get("KOTAK_MPIN", "").strip():
            missing.append("KOTAK_MPIN")
            
        totp_tok = os.environ.get("KOTAK_TOTP_TOKEN", "").strip()
        totp_sec = os.environ.get("KOTAK_TOTP_SECRET", "").strip()
        if not totp_tok and not totp_sec:
            missing.append("KOTAK_TOTP_TOKEN or KOTAK_TOTP_SECRET (either one must be provided)")
            
        if missing:
            logger.error(f"Configuration Validation Failed! Missing values for: {', '.join(missing)}")
            logger.error("Process terminating due to missing configuration.")
            sys.exit(1)

    def _get_totp(self):
        """
        Returns the direct token if provided, or generates it from secret.
        """
        if self.totp_token:
            logger.info("Using KOTAK_TOTP_TOKEN from environment.")
            return self.totp_token
        else:
            logger.info("Generating dynamic TOTP from KOTAK_TOTP_SECRET.")
            try:
                return generate_totp(self.totp_secret)
            except Exception as e:
                logger.error(f"Failed to generate TOTP from secret: {e}")
                logger.error("Process terminating.")
                sys.exit(1)

    def _log_request(self, method, url, headers=None, json_data=None):
        masked_headers = mask_sensitive_headers(headers or {})
        masked_body = mask_sensitive_payload(json_data)
        logger.info(f">>> Request: {method} {url}")
        logger.info(f"    Headers: {json.dumps(masked_headers)}")
        if masked_body is not None:
            logger.info(f"    Body: {json.dumps(masked_body)}")

    def _log_response(self, response, elapsed_time):
        logger.info(f"<<< Response: Status {response.status_code} ({elapsed_time:.2f}s)")
        logger.debug(f"    Headers: {json.dumps(dict(response.headers))}")
        try:
            # Check if response is JSON, format nicely with masking
            resp_json = response.json()
            masked_resp = mask_sensitive_payload(resp_json)
            logger.info(f"    Body (JSON): {json.dumps(masked_resp)}")
        except Exception:
            # If not JSON, print or log snippet of text
            snippet = response.text[:1000]
            logger.info(f"    Body (Raw snippet): {snippet}...")

    def login_flow(self):
        """
        Performs step-by-step authentication login.
        """
        logger.info("Starting authentication flow...")
        
        # Step 1: tradeApiLogin
        login_url = "https://mis.kotaksecurities.com/login/1.0/tradeApiLogin"
        login_headers = {
            "Authorization": self.access_token,
            "neo-fin-key": "neotradeapi",
            "Content-Type": "application/json"
        }
        
        current_totp = self._get_totp()
        login_payload = {
            "mobileNumber": self.mobile_number,
            "ucc": self.ucc,
            "totp": current_totp
        }
        
        self._log_request("POST", login_url, login_headers, login_payload)
        start_time = time.time()
        try:
            response = self.session.post(login_url, headers=login_headers, json=login_payload, verify=self.ssl_verify)
        except Exception as e:
            logger.error(f"Network error during tradeApiLogin: {e}")
            sys.exit(1)
        elapsed = time.time() - start_time
        self._log_response(response, elapsed)
        
        if response.status_code != 200:
            logger.error(f"tradeApiLogin failed with status code {response.status_code}")
            sys.exit(1)
            
        login_data = response.json()
        if login_data.get("status") == "error":
            logger.error(f"tradeApiLogin returned error: {login_data.get('message')}")
            sys.exit(1)
            
        data_block = login_data.get("data", {})
        view_token = data_block.get("token")
        view_sid = data_block.get("sid")
        
        if not view_token or not view_sid:
            logger.error("tradeApiLogin response did not return token or sid.")
            sys.exit(1)
            
        logger.info("Step 1 (tradeApiLogin) successful. Retrieved view token and view sid.")
        
        # Step 2: tradeApiValidate
        validate_url = "https://mis.kotaksecurities.com/login/1.0/tradeApiValidate"
        validate_headers = {
            "Authorization": self.access_token,
            "neo-fin-key": "neotradeapi",
            "sid": view_sid,
            "Auth": view_token,
            "Content-Type": "application/json"
        }
        validate_payload = {
            "mpin": self.mpin
        }
        
        self._log_request("POST", validate_url, validate_headers, validate_payload)
        start_time = time.time()
        try:
            response = self.session.post(validate_url, headers=validate_headers, json=validate_payload, verify=self.ssl_verify)
        except Exception as e:
            logger.error(f"Network error during tradeApiValidate: {e}")
            sys.exit(1)
        elapsed = time.time() - start_time
        self._log_response(response, elapsed)
        
        if response.status_code != 200:
            logger.error(f"tradeApiValidate failed with status code {response.status_code}")
            sys.exit(1)
            
        validate_data = response.json()
        if validate_data.get("status") == "error":
            logger.error(f"tradeApiValidate returned error: {validate_data.get('message')}")
            sys.exit(1)
            
        trade_data = validate_data.get("data", {})
        self.session_token = trade_data.get("token")
        self.session_sid = trade_data.get("sid")
        self.base_url = trade_data.get("baseUrl")
        
        if not self.session_token or not self.session_sid or not self.base_url:
            logger.error("tradeApiValidate response did not return session token, sid, or baseUrl.")
            sys.exit(1)
            
        # Clean trailing slash from base_url if present
        if self.base_url.endswith("/"):
            self.base_url = self.base_url[:-1]
            
        logger.info("Step 2 (tradeApiValidate) successful. Trading session generated.")
        logger.info(f"Base URL set to: {self.base_url}")

    def get_holdings(self, is_retry=False):
        """
        Fetches holdings from portfolio holdings API.
        Automatically re-authenticates if session expires or is invalid.
        """
        # Ensure we are logged in
        if not self.session_token or not self.session_sid or not self.base_url:
            logger.info("No active session details. Initiating login flow...")
            self.login_flow()
            
        holdings_url = f"{self.base_url}/portfolio/v1/holdings"
        headers = {
            "accept": "application/json",
            "Auth": self.session_token,
            "Sid": self.session_sid,
            "neo-fin-key": "neotradeapi"
        }
        
        self._log_request("GET", holdings_url, headers)
        start_time = time.time()
        try:
            response = self.session.get(holdings_url, headers=headers, verify=self.ssl_verify)
        except Exception as e:
            logger.error(f"Network error while fetching holdings: {e}")
            raise e
        elapsed = time.time() - start_time
        self._log_response(response, elapsed)
        
        # Check for token expiration / invalid session
        session_expired = False
        
        # 1. Check status code
        if response.status_code == 401:
            session_expired = True
            
        # 2. Check JSON error payload
        if response.status_code == 200 or response.status_code == 401:
            try:
                resp_json = response.json()
                if resp_json.get("stat") == "Not_Ok":
                    st_code = resp_json.get("stCode")
                    emsg = resp_json.get("emsg", "")
                    if st_code == 1003 or "invalid session" in emsg.lower() or "expired" in emsg.lower():
                        session_expired = True
            except Exception:
                pass
                
        if session_expired:
            if not is_retry:
                logger.warning("Session has expired or is invalid! Triggering auto-reauthentication...")
                # Re-login
                self.login_flow()
                # Retry fetching holdings
                return self.get_holdings(is_retry=True)
            else:
                logger.error("Auto-reauthentication failed to resolve session issue. Terminating.")
                sys.exit(1)
                
        if response.status_code != 200:
            logger.error(f"Failed to fetch holdings. API status code: {response.status_code}")
            
        return response
