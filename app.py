"""
NetGuard - Secure Network Monitor
Flask backend with:
  - Real ARP scanning via Scapy
  - Real ARP spoofing to block devices
  - bcrypt password hashing
  - Fernet-encrypted JSON storage (no pickle)
  - Input validation on every endpoint
  - RBAC (admin/viewer)
  - Rate limiting on auth endpoints

Run as root: sudo python app.py
"""

import os
import re
import sys
import json
import time
import uuid
import threading
import ipaddress
import secrets
import logging
from datetime import datetime, timedelta
from functools import wraps

import bcrypt
from cryptography.fernet import Fernet
from flask import Flask, request, jsonify, session, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import send_file


# Scapy - suppress output
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import ARP, Ether, srp, sendp, conf, get_if_addr, get_if_hwaddr, get_if_list
conf.verb = 0

# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
STORAGE_FILE = os.path.join(BASE_DIR, "data.enc")
KEY_FILE     = os.path.join(BASE_DIR, "storage.key")
SESSION_TIMEOUT = 1800  # 30 min

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = secrets.token_bytes(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

limiter = Limiter(get_remote_address, app=app, default_limits=[])

# ─────────────────────────────────────────────
# Encrypted Storage
# ─────────────────────────────────────────────
def _get_fernet() -> Fernet:
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            key = f.read().strip()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        os.chmod(KEY_FILE, 0o600)
    return Fernet(key)

def load_data() -> dict:
    fernet = _get_fernet()
    if not os.path.exists(STORAGE_FILE):
        return _default_data()
    try:
        with open(STORAGE_FILE, "rb") as f:
            raw = fernet.decrypt(f.read())
        return json.loads(raw.decode())
    except Exception:
        return _default_data()

def save_data(data: dict):
    fernet = _get_fernet()
    encrypted = fernet.encrypt(json.dumps(data, default=str).encode())
    with open(STORAGE_FILE, "wb") as f:
        f.write(encrypted)
    os.chmod(STORAGE_FILE, 0o600)

def _default_data() -> dict:
    # Seed one admin user with hashed password
    admin_pw = "Admin@1234"
    hashed = bcrypt.hashpw(admin_pw.encode(), bcrypt.gensalt(rounds=12)).decode()
    return {
        "users": {
            "admin": {"hash": hashed, "role": "admin"},
        },
        "blocked_macs": [],
        "audit_log": []
    }

# ─────────────────────────────────────────────
# Input Validation
# ─────────────────────────────────────────────
IP_RE   = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
MAC_RE  = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
CIDR_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}/([0-9]|[12][0-9]|3[0-2])$")
USER_RE = re.compile(r"^[a-zA-Z0-9_]{1,32}$")

def valid_ip(v: str) -> bool:
    if not IP_RE.match(v):
        return False
    return all(0 <= int(o) <= 255 for o in v.split("."))

def valid_mac(v: str) -> bool:
    return bool(MAC_RE.match(v))

def valid_cidr(v: str) -> bool:
    if not CIDR_RE.match(v):
        return False
    try:
        ipaddress.ip_network(v, strict=False)
        return True
    except ValueError:
        return False

def valid_username(v: str) -> bool:
    return bool(USER_RE.match(v))

# ─────────────────────────────────────────────
# Audit Logging
# ─────────────────────────────────────────────
def audit(action: str, detail: str, user: str = "system", level: str = "info"):
    data = load_data()
    entry = {
        "id": str(uuid.uuid4())[:8],
        "ts": datetime.utcnow().isoformat(),
        "level": level,
        "user": user,
        "action": action,
        "detail": detail,
        "ip": request.remote_addr if request else "internal"
    }
    data["audit_log"].insert(0, entry)
    data["audit_log"] = data["audit_log"][:200]   # cap at 200 entries
    save_data(data)
    return entry

# ─────────────────────────────────────────────
# RBAC
# ─────────────────────────────────────────────
PERMISSIONS = {
    "admin":  {"scan", "block", "unblock", "view_devices", "view_logs", "manage_users"},
    "viewer": {"view_devices", "view_logs"},
}

def login_required(perm: str = None):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            uid = session.get("user_id")
            if not uid:
                return jsonify({"error": "Unauthorized"}), 401
            # session timeout
            last = session.get("last_active", 0)
            if time.time() - last > SESSION_TIMEOUT:
                session.clear()
                return jsonify({"error": "Session expired"}), 401
            session["last_active"] = time.time()
            if perm:
                role = session.get("role", "")
                if perm not in PERMISSIONS.get(role, set()):
                    audit("ACCESS_DENIED", f"Role '{role}' attempted '{perm}'",
                          session.get("username", "?"), "warn")
                    return jsonify({"error": f"Forbidden: requires '{perm}' permission"}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator

# ─────────────────────────────────────────────
# Network Interface Detection
# ─────────────────────────────────────────────
def detect_interface():
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            if ip and not ip.startswith("127.") and ip != "0.0.0.0":
                return iface, ip
        except Exception:
            continue
    return None, None

# ─────────────────────────────────────────────
# ARP Scanner
# ─────────────────────────────────────────────
def arp_scan(subnet: str, iface: str) -> list:
    """Sends ARP broadcast, returns list of {ip, mac}."""
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    answered, _ = srp(pkt, timeout=3, iface=iface, verbose=0)
    seen = {}
    for _, rcv in answered:
        seen[rcv.hwsrc.lower()] = rcv.psrc
    return [{"ip": ip, "mac": mac} for mac, ip in seen.items()]

# ─────────────────────────────────────────────
# ARP Spoof Engine
# ─────────────────────────────────────────────
_spoof_threads: dict = {}   # mac -> threading.Event

def _spoof_loop(target_ip: str, target_mac: str, gateway_ip: str,
                iface: str, stop_event: threading.Event):
    """
    Continuously send gratuitous ARP replies to target:
      "Gateway IP is at OUR MAC"  → target's traffic hits us → dropped → blocked
    Runs every 1.5 s until stop_event is set.
    """
    try:
        our_mac = get_if_hwaddr(iface)
    except Exception:
        our_mac = "00:00:00:00:00:00"

    pkt = (Ether(dst=target_mac) /
           ARP(op=2, pdst=target_ip, hwdst=target_mac,
               psrc=gateway_ip, hwsrc=our_mac))
    while not stop_event.wait(1.5):
        try:
            sendp(pkt, iface=iface, verbose=0)
        except Exception:
            pass

def start_block(target_ip: str, target_mac: str, gateway_ip: str, iface: str):
    mac = target_mac.lower()
    if mac in _spoof_threads:
        return   # already running
    ev = threading.Event()
    t = threading.Thread(
        target=_spoof_loop,
        args=(target_ip, mac, gateway_ip, iface, ev),
        daemon=True
    )
    _spoof_threads[mac] = ev
    t.start()

def stop_block(target_mac: str):
    mac = target_mac.lower()
    ev = _spoof_threads.pop(mac, None)
    if ev:
        ev.set()

# ─────────────────────────────────────────────
# Auth Routes
# ─────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
@limiter.limit("10/minute")
def api_login():
    body = request.get_json(silent=True) or {}
    username = body.get("username", "").strip()
    password = body.get("password", "")

    # Input validation
    if not valid_username(username):
        return jsonify({"error": "Invalid username format"}), 400
    if not isinstance(password, str) or len(password) > 128:
        return jsonify({"error": "Invalid password"}), 400

    data = load_data()
    user = data["users"].get(username)

    if not user or not bcrypt.checkpw(password.encode(), user["hash"].encode()):
        audit("LOGIN_FAIL", f"Failed login for '{username}'", username, "warn")
        return jsonify({"error": "Invalid credentials"}), 401

    session.clear()
    session["user_id"]    = str(uuid.uuid4())
    session["username"]   = username
    session["role"]       = user["role"]
    session["last_active"] = time.time()

    audit("LOGIN_OK", f"User '{username}' authenticated (role={user['role']})", username, "info")
    return jsonify({"username": username, "role": user["role"]})


@app.route("/api/logout", methods=["POST"])
def api_logout():
    user = session.get("username", "?")
    session.clear()
    audit("LOGOUT", f"User '{user}' logged out", user, "info")
    return jsonify({"ok": True})


@app.route("/api/me")
def api_me():
    if not session.get("user_id"):
        return jsonify({"error": "Not logged in"}), 401
    if time.time() - session.get("last_active", 0) > SESSION_TIMEOUT:
        session.clear()
        return jsonify({"error": "Session expired"}), 401
    session["last_active"] = time.time()
    return jsonify({"username": session["username"], "role": session["role"]})

# ─────────────────────────────────────────────
# Scan Route
# ─────────────────────────────────────────────
@app.route("/api/scan", methods=["POST"])
@login_required("scan")
def api_scan():
    body = request.get_json(silent=True) or {}
    subnet = body.get("subnet", "").strip()

    if not valid_cidr(subnet):
        return jsonify({"error": "Invalid subnet (expected CIDR e.g. 192.168.1.0/24)"}), 400

    iface, _ = detect_interface()
    if not iface:
        return jsonify({"error": "No active network interface found"}), 500

    audit("SCAN", f"ARP scan on {subnet}", session["username"], "info")

    try:
        found = arp_scan(subnet, iface)
    except Exception as e:
        return jsonify({"error": f"Scan failed: {str(e)}"}), 500

    data = load_data()
    blocked = set(data["blocked_macs"])

    devices = []
    for d in found:
        devices.append({
            "ip":      d["ip"],
            "mac":     d["mac"],
            "blocked": d["mac"].lower() in blocked,
        })

    audit("SCAN_DONE", f"Found {len(devices)} device(s) on {subnet}", session["username"], "info")
    return jsonify({"devices": devices, "iface": iface})

# ─────────────────────────────────────────────
# Block / Unblock Routes
# ─────────────────────────────────────────────
@app.route("/api/block", methods=["POST"])
@login_required("block")
def api_block():
    body = request.get_json(silent=True) or {}
    target_ip  = body.get("ip", "").strip()
    target_mac = body.get("mac", "").strip().lower()
    gateway_ip = body.get("gateway", "").strip()

    # Validate all three fields
    if not valid_ip(target_ip):
        return jsonify({"error": "Invalid target IP"}), 400
    if not valid_mac(target_mac):
        return jsonify({"error": "Invalid target MAC"}), 400
    if not valid_ip(gateway_ip):
        return jsonify({"error": "Invalid gateway IP"}), 400

    iface, _ = detect_interface()
    if not iface:
        return jsonify({"error": "No interface"}), 500

    data = load_data()
    if target_mac not in data["blocked_macs"]:
        data["blocked_macs"].append(target_mac)
        save_data(data)

    start_block(target_ip, target_mac, gateway_ip, iface)
    audit("BLOCK", f"Blocking {target_ip} ({target_mac}) via ARP spoof", session["username"], "warn")
    return jsonify({"ok": True, "mac": target_mac})


@app.route("/api/unblock", methods=["POST"])
@login_required("unblock")
def api_unblock():
    body = request.get_json(silent=True) or {}
    target_mac = body.get("mac", "").strip().lower()

    if not valid_mac(target_mac):
        return jsonify({"error": "Invalid MAC address"}), 400

    stop_block(target_mac)

    data = load_data()
    data["blocked_macs"] = [m for m in data["blocked_macs"] if m != target_mac]
    save_data(data)

    audit("UNBLOCK", f"Unblocked {target_mac}", session["username"], "info")
    return jsonify({"ok": True})

# ─────────────────────────────────────────────
# Audit Log Route
# ─────────────────────────────────────────────
@app.route("/api/logs")
@login_required("view_logs")
def api_logs():
    data = load_data()
    return jsonify({"logs": data["audit_log"][:100]})

# ─────────────────────────────────────────────
# Network Info Route
# ─────────────────────────────────────────────
@app.route("/api/netinfo")
@login_required("view_devices")
def api_netinfo():
    iface, ip = detect_interface()
    return jsonify({"iface": iface or "unknown", "ip": ip or "unknown"})

# ─────────────────────────────────────────────
# Serve Frontend
# ─────────────────────────────────────────────
@app.route("/")
def index():
    return send_file("index.html")

# ─────────────────────────────────────────────
# Startup checks
# ─────────────────────────────────────────────
if __name__ == "__main__":
    if os.name != "nt" and os.geteuid() != 0:
        print("[!] Must run as root for ARP operations: sudo python app.py")
        sys.exit(1)

    # Ensure storage is initialized
    if not os.path.exists(STORAGE_FILE):
        save_data(_default_data())
        print("[+] Storage initialized (admin / Admin@1234)")

    iface, ip = detect_interface()
    print(f"[+] Interface: {iface}  IP: {ip}")
    print(f"[+] Storage:   {STORAGE_FILE} (Fernet-encrypted)")
    print(f"[+] Running at http://0.0.0.0:5000")

    app.run(host="0.0.0.0", port=5000, debug=False)
