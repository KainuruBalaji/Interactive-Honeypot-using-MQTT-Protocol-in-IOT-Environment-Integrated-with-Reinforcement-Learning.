import socket
import threading
import json
import paho.mqtt.client as mqtt
import time
import os
import urllib.parse
import sys
import random
import pymongo
from datetime import datetime

MQTT_BROKER = os.getenv("MQTT_BROKER_ADDR", "mqtt_broker")
MONGO_ADDR  = os.getenv("MONGO_ADDR", "mongodb")
MQTT_TOPIC_ALERTS = "honeypot/alerts"
MQTT_TOPIC_ACTIONS = "honeypot/actions/+"

# MongoDB connection for logging uploads
try:
    _mc = pymongo.MongoClient(f"mongodb://{MONGO_ADDR}:27017/", serverSelectionTimeoutMS=3000)
    _db = _mc["honeypot_db"]
    uploads_col = _db["uploads"]
    print("[OK] HTTP trap connected to MongoDB")
except Exception as e:
    uploads_col = None
    print(f"[WARN] HTTP trap MongoDB unavailable: {e}")

ip_attack_counts = {}
ip_mem           = {}

# ── HTTP Session persistence ───────────────────────────────────────────────────
# HTTP is stateless — every browser request is a new TCP connection.
# Without session tracking the brain sees dozens of 0.1s sessions instead of
# one long engagement, making the reward signal useless.
#
# Design:
#   • One logical session per IP, tracked by t0 (start) + last_seen (last req)
#   • SESSION_TIMEOUT = 120s — a human tester browsing slowly must not be cut off
#   • Reaper wakes every 15s, fires SESSION_END only once per expired session
#   • pending_actions[ip] lives in the session dict, NOT deleted on TCP close
#   • t0 is NEVER reset while the attacker is within the timeout window
# ─────────────────────────────────────────────────────────────────────────────
SESSION_TIMEOUT = 120   # seconds idle before session is declared ended

_sessions      = {}     # ip -> {"t0", "last_seen", "cmd_count", "hist", "event", "action"}
_sessions_lock = threading.Lock()


def _sess_get(ip):
    """Return the live session dict for ip, creating one if needed."""
    now = time.time()
    with _sessions_lock:
        if ip in _sessions:
            s = _sessions[ip]
            # still active — just refresh last_seen
            s["last_seen"] = now
            s["cmd_count"] += 1
            return s
        # brand new session
        s = {
            "t0":        now,
            "last_seen": now,
            "cmd_count": 1,
            "hist":      [],
            "event":     threading.Event(),
            "action":    0,
        }
        _sessions[ip] = s
        return s


def _sess_close(ip):
    """Manually close a session (e.g. attacker sent QUIT or connection reset)."""
    with _sessions_lock:
        s = _sessions.pop(ip, None)
    if s:
        dur = round(s["last_seen"] - s["t0"], 2)
        report_end(ip, dur, " | ".join(s["hist"]) or "HTTP session")


def _session_reaper():
    """Background thread: fires SESSION_END for IPs idle > SESSION_TIMEOUT."""
    while True:
        time.sleep(15)
        now = time.time()
        expired = []
        with _sessions_lock:
            for ip, s in list(_sessions.items()):
                if now - s["last_seen"] >= SESSION_TIMEOUT:
                    expired.append((ip, s.copy()))
                    del _sessions[ip]
        for ip, s in expired:
            dur = round(s["last_seen"] - s["t0"], 2)
            report_end(ip, dur, " | ".join(s["hist"]) or "HTTP session")


threading.Thread(target=_session_reaper, daemon=True).start()

def get_mem(ip):
    if ip not in ip_mem:
        ip_mem[ip] = {"requests": 0, "classified": "unknown"}
    return ip_mem[ip]

def on_message(client, userdata, msg):
    try:
        parts = msg.topic.split('/')
        if len(parts) == 3 and parts[1] == "actions":
            ip   = parts[2]
            data = json.loads(msg.payload.decode())
            with _sessions_lock:
                if ip in _sessions:
                    _sessions[ip]["action"] = data.get("action_id", 0)
                    _sessions[ip]["event"].set()
    except:
        pass

listener_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
listener_client.on_message = on_message
try:
    listener_client.connect(MQTT_BROKER, 1883, 60)
    listener_client.subscribe(MQTT_TOPIC_ACTIONS)
    listener_client.loop_start()
    print("[OK] MQTT listener connected")
except Exception as e:
    print(f"[WARN] MQTT broker unavailable: {e} — running without brain")

def ask_brain(ip, body, is_malicious, count, is_scanner):
    total_views = ip_attack_counts.get(ip, 0)
    state = [len(body), is_malicious, count, total_views, is_scanner]
    try:
        listener_client.publish(MQTT_TOPIC_ALERTS, json.dumps({
            "attacker_ip": ip, "service": "HTTP", "action_taken": "PENDING",
            "details": f"Attempt {count} | {body[:80]}", "state_vector": state
        }))
    except: pass

def report_end(ip, dur, detail):
    try:
        listener_client.publish(MQTT_TOPIC_ALERTS, json.dumps({
            "attacker_ip": ip, "service": "HTTP", "action_taken": "SESSION_END",
            "details": detail, "duration": dur, "commands_typed": ip_attack_counts.get(ip, 1)
        }))
    except: pass

# ── HTML pages ─────────────────────────────────────────────────────────────────

LOGIN_PAGE = """\
HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: keep-alive\r\n\r\n
<!DOCTYPE html><html><head><title>SCADA Gateway v4.2 - Login</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0a0a0f;color:#cdd9e5;font-family:'Courier New',monospace;
     display:flex;align-items:center;justify-content:center;min-height:100vh}
.panel{background:#0d1117;border:1px solid #30363d;border-radius:6px;
       padding:40px;width:380px}
.logo{color:#f78166;font-size:11px;letter-spacing:2px;margin-bottom:4px}
h1{color:#79c0ff;font-size:18px;margin-bottom:4px}
.sub{color:#8b949e;font-size:11px;margin-bottom:28px}
label{display:block;color:#8b949e;font-size:11px;margin-bottom:4px;
      text-transform:uppercase;letter-spacing:1px}
input{width:100%;padding:10px 12px;background:#161b22;border:1px solid #30363d;
      color:#cdd9e5;border-radius:4px;margin-bottom:16px;font-family:inherit;font-size:13px}
input:focus{outline:none;border-color:#388bfd}
.btn{width:100%;padding:11px;background:#238636;color:#fff;border:none;
     border-radius:4px;cursor:pointer;font-size:13px;letter-spacing:1px}
.btn:hover{background:#2ea043}
.warn{color:#d29922;font-size:10px;text-align:center;margin-top:14px}
.footer{color:#484f58;font-size:10px;text-align:center;margin-top:18px}
</style></head><body>
<div class="panel">
  <div class="logo">INDUSTRIAL CONTROL SYSTEM</div>
  <h1>SCADA Gateway v4.2</h1>
  <div class="sub">Restricted access — authorized personnel only</div>
  <form action="/login" method="POST">
    <label>Username</label>
    <input type="text" name="user" placeholder="admin" autocomplete="off">
    <label>Password</label>
    <input type="password" name="pass" placeholder="••••••••">
    <button class="btn" type="submit">AUTHENTICATE</button>
  </form>
  <div class="warn">WARNING: Unauthorized access is monitored and prosecuted</div>
  <div class="footer">Node: GW-PROD-001 | Firmware: v4.2.1-stable | TLS 1.3</div>
</div></body></html>"""

def get_recent_uploads():
    """Fetch last 5 uploaded files from MongoDB for the dashboard."""
    if uploads_col is None:
        return []
    try:
        docs = list(uploads_col.find({}, {"_id":0}).sort("timestamp", -1).limit(5))
        return docs
    except:
        return []

def make_dashboard(ip, ts):
    # Fetch recent uploads to show in dashboard
    recent_uploads = get_recent_uploads()
    uploads_rows = ""
    if recent_uploads:
        for u in recent_uploads:
            utime = u.get("timestamp", "")
            if hasattr(utime, "strftime"):
                utime = utime.strftime("%Y-%m-%d %H:%M:%S")
            uploads_rows += (f"<tr><td>{u.get('attacker_ip','?')}</td>"
                             f"<td>{u.get('filename','?')}</td>"
                             f"<td>{u.get('size_bytes',0)} B</td>"
                             f"<td>{utime}</td>"
                             f"<td><a href=\"{u.get('fake_path','#')}\" "
                             f"style=\"color:#f0883e;font-size:10px\">Execute</a></td></tr>")
    else:
        uploads_rows = "<tr><td colspan='5' style='color:#484f58'>No uploads yet</td></tr>"

    interval = random.randint(3, 5)
    uptime_h = random.randint(300, 500)
    return f"""\
HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: keep-alive\r\n\r\n
<!DOCTYPE html><html><head><title>SCADA Dashboard</title>
<!-- DEBUG: API_KEY=AKIAIOSFODNN7EXAMPLE | SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY -->
<!-- DB_PASS=Pr0d_DB_P@ssw0rd_2025! | MQTT_PASS=gw_mqtt_s3cr3t! -->
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#0d0d0d;color:#00ff41;font-family:'Courier New',monospace;padding:16px}}
.topbar{{display:flex;justify-content:space-between;align-items:center;
         border-bottom:1px solid #00ff41;padding-bottom:8px;margin-bottom:16px}}
.logo{{font-size:13px;letter-spacing:2px}}
.status{{font-size:11px;color:#00cc33}}
.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:16px}}
.card{{background:#111;border:1px solid #00882b;padding:12px;border-radius:3px}}
.card .label{{font-size:10px;color:#00882b;letter-spacing:1px;margin-bottom:6px}}
.card .val{{font-size:20px}}
.card .sub{{font-size:10px;color:#00882b;margin-top:4px}}
.ok{{color:#00ff41}}.warn{{color:#e3b341}}.crit{{color:#f85149}}
table{{width:100%;border-collapse:collapse;font-size:11px;margin-bottom:16px}}
th{{background:#0a1a0a;color:#00882b;padding:6px 8px;text-align:left;
    border-bottom:1px solid #00882b;letter-spacing:1px}}
td{{padding:5px 8px;border-bottom:1px solid #0a2a0a}}
.log{{background:#050a05;border:1px solid #00882b;padding:10px;height:110px;
      overflow-y:auto;font-size:10px;margin-bottom:12px}}
.ping-section{{background:#111;border:1px solid #00882b;padding:14px;border-radius:3px;margin-bottom:12px}}
.ping-section h3{{color:#00882b;font-size:11px;letter-spacing:1px;margin-bottom:10px}}
.ping-row{{display:flex;gap:8px}}
.ping-input{{flex:1;padding:7px 10px;background:#050a05;border:1px solid #00882b;
             color:#00ff41;font-family:inherit;font-size:12px;border-radius:2px}}
.ping-btn{{padding:7px 16px;background:#1a3a1a;border:1px solid #00882b;
           color:#00ff41;cursor:pointer;font-family:inherit;font-size:12px}}
.ping-out{{margin-top:8px;font-size:10px;color:#00cc33;min-height:20px}}
.nav a{{color:#388bfd;font-size:11px;margin-right:16px;text-decoration:none}}
</style></head><body>
<div class="topbar">
  <div class="logo">SCADA GATEWAY — ADMIN DASHBOARD</div>
  <div class="status" id="clk">LIVE</div>
</div>
<div class="nav">
  <a href="/devices">Devices</a>
  <a href="/firmware">Firmware Upload</a>
  <a href="/logs">System Logs</a>
  <a href="/config">Network Config</a>
  <a href="/api/keys">API Keys</a>
</div><br>
<div class="grid">
  <div class="card"><div class="label">GATEWAY STATUS</div>
    <div class="val ok">ONLINE</div>
    <div class="sub">Uptime: <span id="up">{uptime_h}h 22m</span></div></div>
  <div class="card"><div class="label">MQTT BROKER</div>
    <div class="val ok">ACTIVE</div>
    <div class="sub">Msg/s: <span id="mps">--</span></div></div>
  <div class="card"><div class="label">DEVICES ONLINE</div>
    <div class="val" id="dcnt">--</div>
    <div class="sub">Last sync: <span id="dsync">--</span></div></div>
  <div class="card"><div class="label">CPU / TEMP</div>
    <div class="sub">CPU: <span id="cpu">--</span>% | <span id="tmp">--</span>°C</div>
    <div class="sub">MEM: <span id="mem">--</span> MB free</div></div>
</div>
<h3 style="color:#00882b;font-size:11px;letter-spacing:1px;margin-bottom:6px">CONNECTED DEVICES</h3>
<table><tr><th>DEVICE ID</th><th>TYPE</th><th>IP</th><th>LAST SEEN</th><th>STATUS</th></tr>
  <tr><td>sensor-001</td><td>Temperature</td><td>192.168.10.11</td>
      <td id="d1">--</td><td class="ok">ONLINE</td></tr>
  <tr><td>cam-002</td><td>IP Camera</td><td>192.168.10.22</td>
      <td id="d2">--</td><td class="ok">ONLINE</td></tr>
  <tr><td>relay-003</td><td>Power Relay</td><td>192.168.10.33</td>
      <td id="d3">--</td><td class="warn">WARNING</td></tr>
  <tr><td>plc-004</td><td>PLC Controller</td><td>192.168.10.44</td>
      <td id="d4">--</td><td class="ok">ONLINE</td></tr>
</table>
<div class="log" id="log">
  [{ts}] System boot complete — all services started<br>
  [{ts}] MQTT broker listening on :1883 (TLS)<br>
  [{ts}] 4 devices registered and connected<br>
  [{ts}] Admin login from {ip}<br>
</div>
<div class="ping-section">
  <h3>NETWORK DIAGNOSTICS — PING TOOL</h3>
  <div class="ping-row">
    <input class="ping-input" id="ping-host" placeholder="hostname or IP (e.g. 192.168.10.1)">
    <button class="ping-btn" onclick="doPing()">RUN</button>
  </div>
  <div class="ping-out" id="ping-out"></div>
</div>
<h3 style="color:#00882b;font-size:11px;letter-spacing:1px;margin-bottom:6px">
  CREDENTIALS &amp; API KEYS (internal use)
</h3>
<table><tr><th>SERVICE</th><th>KEY / VALUE</th></tr>
  <tr><td>MQTT Username</td><td>iot-gateway-prod</td></tr>
  <tr><td>MQTT Password</td><td>gw_mqtt_s3cr3t!</td></tr>
  <tr><td>AWS Key ID</td><td>AKIAIOSFODNN7EXAMPLE</td></tr>
  <tr><td>AWS Secret</td><td>wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</td></tr>
  <tr><td>DB Password</td><td>Pr0d_DB_P@ssw0rd_2025!</td></tr>
</table>
<h3 style="color:#f0883e;font-size:11px;letter-spacing:1px;margin:14px 0 6px">
  FIRMWARE UPLOADS (security team review required)
</h3>
<table><tr><th>ATTACKER IP</th><th>FILENAME</th><th>SIZE</th><th>TIMESTAMP</th><th>ACTION</th></tr>
  {uploads_rows}
</table>
<script>
function ri(a,b){{return Math.floor(Math.random()*(b-a+1))+a;}}
function now(){{return new Date().toLocaleTimeString();}}
function doPing(){{
  var h=document.getElementById('ping-host').value||'192.168.10.1';
  var o=document.getElementById('ping-out');
  o.textContent='Running ping to '+h+'...';
  setTimeout(function(){{
    o.innerHTML='PING '+h+': 56(84) bytes<br>'
      +'64 bytes from '+h+': icmp_seq=1 ttl=64 time='+ri(1,8)+'.'+ri(1,9)+'ms<br>'
      +'64 bytes from '+h+': icmp_seq=2 ttl=64 time='+ri(1,8)+'.'+ri(1,9)+'ms<br>'
      +'64 bytes from '+h+': icmp_seq=3 ttl=64 time='+ri(1,8)+'.'+ri(1,9)+'ms<br>'
      +'3 packets transmitted, 3 received, 0% packet loss';
  }}, ri(800,1800));
}}
function tick(){{
  document.getElementById('clk').textContent='['+now()+'] LIVE';
  document.getElementById('mps').textContent=ri(12,38);
  document.getElementById('dcnt').textContent=ri(3,4);
  document.getElementById('dsync').textContent=now();
  document.getElementById('cpu').textContent=ri(8,35);
  document.getElementById('tmp').textContent=ri(42,58);
  document.getElementById('mem').textContent=ri(210,290);
  ['d1','d2','d3','d4'].forEach(function(id){{document.getElementById(id).textContent=now();}});
  var log=document.getElementById('log');
  var msgs=['sensor-001: '+ri(22,28)+'.'+ri(1,9)+'°C',
            'cam-002 heartbeat OK',
            'relay-003 threshold '+ri(85,99)+'%',
            'plc-004 modbus poll OK'];
  log.innerHTML+='<br>['+now()+'] '+msgs[ri(0,3)];
  log.scrollTop=log.scrollHeight;
}}
tick(); setInterval(tick,{interval}000);
</script></body></html>"""

def make_admin_panel():
    return """\
HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: keep-alive\r\n\r\n
<!DOCTYPE html><html><head><title>Device Manager</title>
<style>
body{background:#0d1117;color:#c9d1d9;font-family:'Courier New',monospace;padding:20px}
h2{color:#79c0ff;font-size:15px;border-bottom:1px solid #30363d;padding-bottom:8px;margin-bottom:14px}
table{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:16px}
th{background:#161b22;color:#79c0ff;padding:8px;text-align:left;border:1px solid #30363d}
td{padding:8px;border:1px solid #21262d}
.btn{padding:4px 10px;background:#238636;color:#fff;border:none;cursor:pointer;
     border-radius:3px;font-size:11px}
.upload{background:#161b22;border:1px solid #30363d;padding:14px;border-radius:4px;margin-bottom:12px}
.upload h3{color:#79c0ff;font-size:12px;margin-bottom:10px}
.file-input{background:#0d1117;border:1px solid #388bfd;color:#c9d1d9;padding:6px;
            border-radius:3px;font-size:12px;margin-right:8px}
.upload-btn{padding:6px 14px;background:#1f6feb;color:#fff;border:none;cursor:pointer;
            border-radius:3px;font-size:12px}
.result{color:#3fb950;font-size:11px;margin-top:8px}
a{color:#388bfd;font-size:11px;margin-right:14px;text-decoration:none}
pre{background:#161b22;padding:10px;font-size:11px;color:#3fb950;border-radius:3px}
</style></head><body>
<div><a href="/">Dashboard</a><a href="/devices">Devices</a>
<a href="/firmware">Firmware</a><a href="/logs">Logs</a>
<a href="/config">Config</a><a href="/api/keys">API Keys</a></div><br>
<h2>Device Management Panel</h2>
<table><tr><th>Device</th><th>IP</th><th>Firmware</th><th>Status</th><th>Actions</th></tr>
<tr><td>sensor-001</td><td>192.168.10.11</td><td>v1.4.2</td><td style="color:#3fb950">Online</td>
    <td><button class="btn">Reboot</button> <button class="btn">Update</button></td></tr>
<tr><td>cam-002</td><td>192.168.10.22</td><td>v2.1.0</td><td style="color:#3fb950">Online</td>
    <td><button class="btn">Reboot</button> <button class="btn">Update</button></td></tr>
<tr><td>relay-003</td><td>192.168.10.33</td><td>v1.2.1</td><td style="color:#e3b341">Warning</td>
    <td><button class="btn">Reboot</button> <button class="btn">Update</button></td></tr>
</table>
<div class="upload">
  <h3>FIRMWARE UPLOAD</h3>
  <form action="/firmware/upload" method="POST" enctype="multipart/form-data">
    <input class="file-input" type="file" name="firmware" accept=".bin,.img,.tar.gz">
    <button class="upload-btn" type="submit">UPLOAD FIRMWARE</button>
  </form>
  <div class="result" id="upres"></div>
</div>
<h2>SSH Access Credentials</h2>
<pre>Host: 192.168.10.5
Port: 22
User: admin
Pass: Adm!n_2025!
Key : /etc/ssh/id_rsa (see /api/keys)</pre>
</body></html>"""

def make_api_keys_page():
    return """\
HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: keep-alive\r\n\r\n
<!DOCTYPE html><html><head><title>API Key Management</title>
<style>body{background:#0d1117;color:#c9d1d9;font-family:'Courier New',monospace;padding:20px}
h2{color:#f78166;font-size:14px}
pre{background:#161b22;padding:12px;font-size:11px;color:#3fb950;border-radius:3px;margin-bottom:12px}
a{color:#388bfd;font-size:11px;margin-right:14px;text-decoration:none}
</style></head><body>
<div><a href="/">Dashboard</a><a href="/devices">Devices</a><a href="/firmware">Firmware</a></div><br>
<h2>API Key Management — RESTRICTED</h2>
<pre>AWS_ACCESS_KEY_ID     = AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION    = us-east-1
AWS_S3_BUCKET         = iot-backups-prod</pre>
<pre>MQTT_BROKER    = iot-prod.internal.example.com:8883
MQTT_USER      = iot-gateway-prod
MQTT_PASSWORD  = gw_mqtt_s3cr3t!
INFLUX_TOKEN   = influx_fake_abcdef1234567890abcdef</pre>
<pre>DB_HOST        = 192.168.10.20
DB_NAME        = iot_prod
DB_USER        = iotadmin
DB_PASSWORD    = Pr0d_DB_P@ssw0rd_2025!</pre>
<pre># Private SSH Key (gateway)
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4PAtEsH
fakePrivateKeyDataLooksRealButIsCompletelyUseless
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
-----END RSA PRIVATE KEY-----</pre>
</body></html>"""

def make_logs_page(ip):
    return f"""\
HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: keep-alive\r\n\r\n
<!DOCTYPE html><html><head><title>System Logs</title>
<style>body{{background:#0d0d0d;color:#00ff41;font-family:'Courier New',monospace;padding:20px}}
pre{{font-size:11px;line-height:1.6}}a{{color:#388bfd;font-size:11px;margin-right:14px;text-decoration:none}}</style></head><body>
<div><a href="/">Dashboard</a><a href="/devices">Devices</a><a href="/api/keys">API Keys</a></div><br>
<pre>
[2026-04-02 14:00:01] system  : boot complete
[2026-04-02 14:00:02] mqtt    : broker started :1883
[2026-04-02 14:00:05] sensor-001: connected pass=Mqtt_Pr0d_2025!
[2026-04-02 14:00:06] cam-002 : connected
[2026-04-02 14:20:01] sshd    : login admin from 192.168.1.50
[2026-04-02 14:22:09] sshd    : login root  from 192.168.1.50
[2026-04-02 {time.strftime('%H:%M:%S')}] http    : admin login from {ip}
[2026-04-02 {time.strftime('%H:%M:%S')}] system  : session active
</pre>
</body></html>"""

def make_config_page():
    return """\
HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: keep-alive\r\n\r\n
<!DOCTYPE html><html><head><title>Network Config</title>
<style>body{background:#0d1117;color:#c9d1d9;font-family:'Courier New',monospace;padding:20px}
h2{color:#79c0ff;font-size:14px}
pre{background:#161b22;padding:12px;font-size:11px;border-radius:3px;margin-bottom:10px}
a{color:#388bfd;font-size:11px;margin-right:14px;text-decoration:none}
</style></head><body>
<div><a href="/">Dashboard</a><a href="/devices">Devices</a><a href="/api/keys">API Keys</a></div><br>
<h2>Network Configuration</h2>
<pre>eth0: 192.168.10.5/24  gw: 192.168.10.1
mqtt: iot-prod.internal.example.com:8883 (TLS)
db  : 192.168.10.20:5432
ssh : 0.0.0.0:22</pre>
<h2>Internal Service Map</h2>
<pre>192.168.10.5   - SCADA Gateway (this device)
192.168.10.11  - Temperature Sensor
192.168.10.20  - PostgreSQL DB   (db_user=iotadmin db_pass=Pr0d_DB_P@ssw0rd_2025!)
192.168.10.22  - IP Camera       (rtsp://192.168.10.22:554/live pass=cam_r00t!)
192.168.10.33  - Power Relay
192.168.10.44  - PLC Controller  (modbus TCP :502)</pre>
</body></html>"""

def make_firmware_upload_success(filename):
    safe_name = filename.replace("/","").replace("\\","") or "upload.bin"
    fake_path = f"/var/www/uploads/{safe_name}"
    return f"""\
HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: keep-alive\r\n\r\n
<!DOCTYPE html><html><head><title>Upload Complete</title>
<style>body{{background:#0d1117;color:#3fb950;font-family:'Courier New',monospace;padding:30px}}
pre{{background:#161b22;padding:12px;font-size:12px;border-radius:3px;margin:10px 0}}
a{{color:#388bfd;font-size:11px;text-decoration:none;margin-right:12px}}
</style></head><body>
<h2 style="color:#3fb950">Firmware Upload Successful</h2>
<pre>File   : {safe_name}
Saved  : {fake_path}
Status : Staged for deployment
SHA256 : a3f8d2e1b4c9f0713628e5a0d1c4b7f2e8a1d3c6b9f2e5a8d1c4b7f0e3a6d9c2</pre>
<p style="font-size:12px">The firmware has been saved. To execute:</p>
<pre>curl http://localhost/api/exec?cmd=chmod+755+{fake_path}
curl http://localhost/api/exec?cmd={fake_path}</pre>
<a href="/">Dashboard</a><a href="/firmware">Upload Another</a>
</body></html>"""

def make_shell_page(path):
    return f"""\
HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: keep-alive\r\n\r\n
<!DOCTYPE html><html><head><title>Shell</title>
<style>body{{background:#0d0d0d;color:#00ff41;font-family:'Courier New',monospace;padding:20px}}
.out{{background:#050a05;border:1px solid #00882b;padding:12px;font-size:12px;
      height:200px;overflow-y:auto;margin-bottom:10px}}
.row{{display:flex;gap:8px}}
input{{flex:1;background:#050a05;border:1px solid #00882b;color:#00ff41;
       padding:7px;font-family:inherit;font-size:12px}}
button{{padding:7px 14px;background:#0a2a0a;border:1px solid #00882b;
        color:#00ff41;cursor:pointer;font-family:inherit}}
</style></head><body>
<div style="font-size:11px;margin-bottom:8px">
  Executing: <span style="color:#f0883e">{path}</span> — Web shell interface
</div>
<div class="out" id="out">
sh: {path}: Disk I/O error — filesystem busy<br>
Retrying... (1/3)<br>
Retrying... (2/3)<br>
sh: Timeout waiting for filesystem<br>
</div>
<div class="row">
  <input id="cmd" placeholder="command">
  <button onclick="runCmd()">EXEC</button>
</div>
<script>
function ri(a,b){{return Math.floor(Math.random()*(b-a+1))+a;}}
function runCmd(){{
  var c=document.getElementById('cmd').value; if(!c) return;
  var o=document.getElementById('out');
  o.innerHTML+='<br><span style="color:#00cc33">$ '+c+'</span>';
  setTimeout(function(){{
    var r='sh: '+c+': command not found';
    if(c.includes('cat'))r='cat: permission denied (read-only filesystem)';
    else if(c.includes('ls'))r='.: Permission denied';
    else if(c.includes('id'))r='uid=33(www-data) gid=33(www-data)';
    else if(c.includes('pwd'))r='/var/www/uploads';
    else if(c.includes('wget')||c.includes('curl'))r='curl: (6) Could not resolve host: network unreachable';
    o.innerHTML+='<br>'+r;
    o.scrollTop=o.scrollHeight;
  }},ri(400,1200));
}}
</script></body></html>"""

def make_waf_block():
    inc = random.randint(10000,99999)
    return (f"HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nConnection: keep-alive\r\n\r\n"
            f"<html><body style='background:#1a0a0a;color:#f85149;font-family:monospace;padding:30px'>"
            f"<h2>403 Forbidden — WAF Block</h2>"
            f"<p>Malicious payload detected. Incident ID: {inc}</p>"
            f"<p style='color:#8b949e;font-size:12px'>This event has been logged and reported.</p>"
            f"<a href='/login' style='color:#388bfd;font-size:12px'>Return to login</a>"
            f"</body></html>")

def make_tarpit_response():
    return ("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: keep-alive\r\n\r\n"
            "<html><body style='background:#1a1a2e;color:#f55;text-align:center;"
            "padding-top:80px;font-family:monospace'>"
            "<h2>Authentication Failed</h2>"
            "<p style='color:#888;font-size:12px'>Invalid credentials. Attempt logged.</p>"
            "<a href='/login' style='color:#388bfd;font-size:12px'>Try again</a>"
            "</body></html>")

def make_captcha_page():
    return ("HTTP/1.1 429 Too Many Requests\r\nRetry-After: 30\r\n"
            "Content-Type: text/html\r\nConnection: keep-alive\r\n\r\n"
            "<html><body style='background:#1a1a2e;color:#eee;text-align:center;"
            "padding-top:80px;font-family:monospace'>"
            "<h2>Rate Limit Exceeded</h2>"
            "<p style='color:#888;font-size:12px'>Too many attempts. Complete verification.</p>"
            "<div style='background:#16213e;display:inline-block;padding:28px;"
            "border-radius:6px;margin-top:16px'>"
            "<p style='color:#888'>[ hCaptcha Verification ]</p>"
            "<p style='color:#555;font-size:11px'>Please wait 30 seconds before retrying.</p>"
            "</div></body></html>")

# ── URL router ─────────────────────────────────────────────────────────────────
def route_get(path, ip):
    if path in ("/", "/login"):
        return LOGIN_PAGE.encode()
    elif path == "/devices":
        return make_admin_panel().encode()
    elif path == "/api/keys":
        return make_api_keys_page().encode()
    elif path.startswith("/logs"):
        return make_logs_page(ip).encode()
    elif path == "/config":
        return make_config_page().encode()
    elif path == "/firmware":
        return make_admin_panel().encode()
    elif path.startswith("/var/www/uploads/") or path.startswith("/uploads/"):
        fname = path.split("/")[-1]
        return make_shell_page(path).encode()
    else:
        # Any unknown URL — serve a page that links back in (no dead ends)
        return (f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: keep-alive\r\n\r\n"
                f"<html><body style='background:#0d1117;color:#c9d1d9;font-family:monospace;padding:20px'>"
                f"<h2 style='color:#79c0ff'>IoT Gateway</h2>"
                f"<p style='font-size:12px'>Resource: {path}</p>"
                f"<p style='font-size:12px'>Redirecting...</p>"
                f"<a href='/login' style='color:#388bfd;font-size:12px'>Login</a> "
                f"<a href='/devices' style='color:#388bfd;font-size:12px'>Devices</a>"
                f"</body></html>").encode()

def handle_attacker(client_socket, addr):
    ip = addr[0]

    try:
        while True:
            client_socket.settimeout(30.0)
            try:
                raw = client_socket.recv(4096).decode(errors='ignore')
            except:
                break
            if not raw:
                break

            parts   = raw.split('\r\n\r\n', 1)
            headers = parts[0]
            body    = urllib.parse.unquote_plus(parts[1]) if len(parts) > 1 else ""
            lines   = headers.split('\r\n')
            rl      = lines[0].split(' ')
            method  = rl[0] if rl else "GET"
            path    = rl[1] if len(rl) > 1 else "/"

            # ── Get or create the persistent session for this IP ──────────
            # _sess_get() updates last_seen and increments cmd_count on every
            # call, so the session stays alive as long as the browser is active.
            sess = _sess_get(ip)

            # Keep global ip_attack_counts in sync for classifier
            if ip not in ip_attack_counts:
                ip_attack_counts[ip] = 0

            # ── GET: serve page, count visit, do not ask brain ────────────
            if method == "GET":
                ip_attack_counts[ip] += 1
                client_socket.sendall(route_get(path, ip))
                continue

            # ── POST /firmware/upload ─────────────────────────────────────
            if path == "/firmware/upload":
                fname = "firmware.bin"
                for line in lines:
                    if "filename=" in line.lower():
                        fname = line.split("filename=")[-1].strip().strip('"')
                upload_size = len(body.encode()) if body else 0
                fake_path   = f"/var/www/uploads/{fname}"

                if uploads_col is not None:
                    try:
                        uploads_col.insert_one({
                            "timestamp":   datetime.now(),
                            "attacker_ip": ip,
                            "filename":    fname,
                            "fake_path":   fake_path,
                            "size_bytes":  upload_size,
                            "service":     "HTTP",
                            "sha256":      "a3f8d2e1b4c9f0713628e5a0d1c4b7f2e8a1d3c6b9f2e5a8d1c4b7f0e3a6d9c2",
                        })
                    except:
                        pass

                sess["hist"].append(f"FIRMWARE_UPLOAD:{fname}:{upload_size}b")
                ip_attack_counts[ip] += 1
                eng_depth = sess["cmd_count"]
                ask_brain(ip, f"FIRMWARE_UPLOAD:{fname}", 1, eng_depth, 0)
                client_socket.sendall(make_firmware_upload_success(fname).encode())
                continue

            # ── POST login attempt — ask brain ────────────────────────────
            ip_attack_counts[ip] += 1

            malicious = ["'", '"', "or ", "and ", "=", ";", "--",
                         "union", "select", "drop", "1=1", "<script"]
            is_mal  = 1 if any(c in body.lower() for c in malicious) else 0
            is_scan = 1 if (ip_attack_counts[ip] > 5 and len(body) < 20) else 0

            sess["hist"].append(f"POST:{body[:60]}")

            # Use the session's cumulative cmd_count as eng_depth so the
            # brain sees the full depth of engagement, not per-connection count
            eng_depth = sess["cmd_count"]

            # Re-use the session's event/action so the same threading.Event
            # is shared across all TCP connections from this IP
            sess["event"].clear()
            ask_brain(ip, body, is_mal, eng_depth, is_scan)

            ok  = sess["event"].wait(3.0)
            act = sess["action"] if ok else 0
            ts  = time.strftime("%Y-%m-%d %H:%M:%S")

            if act == 0:
                client_socket.sendall(make_dashboard(ip, ts).encode())
            elif act == 1:
                time.sleep(0.8)
                client_socket.sendall(make_admin_panel().encode())
            elif act == 2:
                time.sleep(2.0)
                client_socket.sendall(make_waf_block().encode())
            elif act == 3:
                time.sleep(random.uniform(4.0, 7.0))
                client_socket.sendall(make_tarpit_response().encode())
            elif act == 4:
                time.sleep(1.5)
                client_socket.sendall(make_captcha_page().encode())

            # SESSION_END is NOT fired here.
            # The _session_reaper thread fires it after SESSION_TIMEOUT (120s)
            # of complete inactivity, so dur = full engagement time.

    except:
        pass
    finally:
        # TCP close does NOT mean attacker left — browser may reconnect.
        # The reaper fires SESSION_END after SESSION_TIMEOUT (120s) of silence.
        try:
            client_socket.close()
        except:
            pass

def start_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 5000))
    srv.listen(100)
    print("[*] HTTP Trap on port 5000...")
    while True:
        s, a = srv.accept()
        threading.Thread(target=handle_attacker, args=(s,a), daemon=True).start()

if __name__ == "__main__":
    sys.stdout.reconfigure(line_buffering=True)
    start_server()
