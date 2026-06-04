import socket
import threading
import json
import paho.mqtt.client as mqtt
import time
import os
import sys
import random

MQTT_BROKER = os.getenv("MQTT_BROKER_ADDR", "mqtt_broker")
MQTT_TOPIC_ALERTS = "honeypot/alerts"
MQTT_TOPIC_ACTIONS = "honeypot/actions/+"

pending_actions = {}

def on_message(client, userdata, msg):
    try:
        parts = msg.topic.split('/')
        if len(parts) == 3 and parts[1] == "actions":
            ip = parts[2]
            data = json.loads(msg.payload.decode())
            if ip in pending_actions:
                pending_actions[ip]["action"] = data.get("action_id", 0)
                pending_actions[ip]["event"].set()
    except: pass

listener_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
listener_client.on_message = on_message
listener_client.connect(MQTT_BROKER, 1883, 60)
listener_client.subscribe(MQTT_TOPIC_ACTIONS)
listener_client.loop_start()

def mqtt_pub(d):
    try:
        c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        c.connect(MQTT_BROKER, 1883, 60)
        c.publish(MQTT_TOPIC_ALERTS, json.dumps(d))
        c.disconnect()
    except: pass

def ask_brain(ip, cmd, cmd_n, login_att):
    hi = ["wget","curl","rm","chmod","python","perl","sh","nc","bash","dd","tftp","ftpget"]
    t = 5 if any(cmd.startswith(x) for x in hi) else 1
    mqtt_pub({"attacker_ip":ip,"service":"TELNET","action_taken":"PENDING",
              "details":f"Typed:{cmd}",
              "state_vector":[len(cmd), cmd_n, t, login_att, cmd_n]})

def report_end(ip, dur, hist):
    mqtt_pub({"attacker_ip":ip,"service":"TELNET","action_taken":"SESSION_END",
              "details":" | ".join(hist) if hist else "No commands.",
              "duration":dur,"commands_typed":len(hist)})

# ── Fake filesystem ────────────────────────────────────────────────────────────
FS = {
    "/":    ["bin","etc","var","tmp","mnt","usr","proc"],
    "/etc": ["passwd","shadow","config","init.d","hosts","resolv.conf"],
    "/var": ["log","run","tmp"],
    "/var/log": ["messages","auth.log","system.log"],
    "/tmp": [],
    "/mnt": ["usb0","usb1"],
    "/proc":["cpuinfo","meminfo","version","net"],
    "/usr": ["bin","lib","share"],
}

# NVRAM-style config dump — the "accidental" data leak (Action 4)
NVRAM_DUMP = (
    b"\r\n*** NVRAM Configuration Dump ***\r\n"
    b"device_model=IoT-GW-2000\r\n"
    b"device_serial=GW2K-202600001337\r\n"
    b"firmware_ver=2.1.4-stable\r\n"
    b"admin_username=admin\r\n"
    b"admin_password=r0uter@dm1n!\r\n"
    b"wifi_ssid=IoT-Internal-Net\r\n"
    b"wifi_pass=W1fi_S3cr3t_2025!\r\n"
    b"mqtt_host=192.168.10.50\r\n"
    b"mqtt_port=1883\r\n"
    b"mqtt_user=iot-gateway\r\n"
    b"mqtt_pass=Mqtt_Pr0d_2025!\r\n"
    b"db_host=192.168.10.20\r\n"
    b"db_pass=Pr0d_DB_P@ssw0rd_2025!\r\n"
    b"internal_ip=192.168.10.5\r\n"
    b"gateway_ip=192.168.10.1\r\n"
    b"cam_rtsp=rtsp://192.168.10.22:554/live\r\n"
    b"cam_pass=cam_r00t!\r\n"
    b"*** End of NVRAM Dump ***\r\n"
)

FILE_CONTENTS = {
    "/etc/passwd":   b"root::0:0:root:/root:/bin/sh\nadmin:x:1000:1000::/home/admin:/bin/sh\r\n",
    "/etc/shadow":   b"root:$1$fakeHash$AAAAAAAAAAAAAAAAAAAAAAAA.:19800:0:99999:7:::\r\n",
    "/etc/config":   b"lan_ip=192.168.10.5\nmqtt_pass=Mqtt_Pr0d_2025!\nwifi_pass=W1fi_S3cr3t_2025!\r\n",
    "/etc/hosts":    b"127.0.0.1 localhost\n192.168.10.5 iot-gateway\n192.168.10.20 db-server\r\n",
    "/proc/cpuinfo": b"processor\t: 0\nmodel name\t: ARMv7 Processor rev 4\nhardware\t: IoT-GW-2000\r\n",
    "/proc/version": b"Linux version 3.10.108 (IoT-GW-2000) gcc version 4.8.5\r\n",
    "/proc/meminfo": b"MemTotal:        128000 kB\nMemFree:          38400 kB\nBuffers:          12800 kB\r\n",
}


def exec_cmd(conn, cmd, base, args, cdir, fs, fc):
    """Pure function — no closures. Returns (status_str, updated_cdir)."""
    if base == "help":
        conn.send(b"Built-ins: cd ls cat pwd id whoami hostname uname ps ifconfig "
                  b"echo rm mkdir wget curl reboot\r\n")
    elif base == "cd":
        t = args[0] if args else "/"
        if t == "~": t = "/"
        elif t == "..": t = cdir.rsplit("/", 1)[0] or "/"
        elif not t.startswith("/"): t = (cdir.rstrip("/") + "/" + t).replace("//", "/")
        t = t.replace("//", "/")
        if t in fs:
            cdir = t
        else:
            conn.send(f"ash: cd: {t}: No such file or directory\r\n".encode())
    elif base == "ls":
        d = cdir
        for a in args:
            if not a.startswith("-"):
                c = (a if a.startswith("/") else cdir.rstrip("/") + "/" + a).replace("//", "/")
                if c in fs: d = c
        if d in fs:
            if any(x in cmd for x in ["-l", "-la", "-al"]):
                out = "total 48\r\n"
                for f in fs[d]:
                    is_dir = (d.rstrip("/")+"/"+f) in fs or f in fs
                    p = "drwxr-xr-x" if is_dir else "-rw-r--r--"
                    out += f"{p} 1 root root {random.randint(512,32768):6d} Apr  2 {f}\r\n"
            else:
                out = "  ".join(fs[d]) + "\r\n" if fs[d] else "\r\n"
            conn.send(out.encode())
        else:
            conn.send(f"ls: {d}: No such file or directory\r\n".encode())
    elif base == "cat":
        req = args[0] if args else ""
        fp = (req if req.startswith("/") else cdir.rstrip("/") + "/" + req).replace("//", "/")
        if fp in fc:
            conn.send(fc[fp])
            if not fc[fp].endswith(b"\r\n"): conn.send(b"\r\n")
        else:
            conn.send(f"cat: {req}: No such file or directory\r\n".encode())
    elif base == "pwd":
        conn.send(f"{cdir}\r\n".encode())
    elif base == "id":
        conn.send(b"uid=0(root) gid=0(root) groups=0(root)\r\n")
    elif base == "whoami":
        conn.send(b"root\r\n")
    elif base == "hostname":
        conn.send(b"IoT-GW-2000\r\n")
    elif base == "uname":
        if "-a" in cmd: conn.send(b"Linux IoT-GW-2000 3.10.108 armv7l GNU/Linux\r\n")
        else: conn.send(b"Linux\r\n")
    elif base == "ps":
        conn.send(b"  PID USER  COMMAND\r\n"
                  b"    1 root  /sbin/init\r\n"
                  b"   12 root  /sbin/syslogd\r\n"
                  b"  412 root  /usr/sbin/telnetd\r\n"
                  b"  501 root  /opt/iot-gateway/gateway\r\n"
                  b"  889 root  mosquitto\r\n")
    elif base == "ifconfig":
        conn.send(b"br-lan   inet addr:192.168.10.5  Mask:255.255.255.0\r\n"
                  b"         HWaddr 00:11:22:33:44:55  UP BROADCAST RUNNING\r\n")
    elif base == "echo":
        conn.send((" ".join(args) + "\r\n").encode())
    elif base in ("rm", "rmdir"):
        fname = args[0].split("/")[-1] if args else ""
        if fname in fs.get(cdir, []): fs[cdir].remove(fname)
    elif base in ("mkdir", "mkfifo"):
        dname = args[0] if args else "newdir"
        full = (cdir.rstrip("/") + "/" + dname).replace("//", "/")
        fs[full] = []
        if dname not in fs.get(cdir, []): fs[cdir].append(dname)
    elif base == "reboot":
        conn.send(b"Rebooting system...\r\n")
        time.sleep(1.5)
        conn.send(b"\r\nConnection closed by remote host.\r\n")
        return "REBOOT", cdir
    elif base in ("wget", "curl"):
        url = args[-1] if args else "http://unknown"
        conn.send(f"Connecting to {url}... failed: Network unreachable\r\n".encode())
    else:
        conn.send(f"ash: {base}: command not found\r\n".encode())
    return "OK", cdir


def handle_attacker(conn, addr):
    ip = addr[0]
    t0 = time.time()
    hist = []
    pending_actions[ip] = {"event": threading.Event(), "action": 0}

    fs = {k: list(v) for k, v in FS.items()}
    fc = dict(FILE_CONTENTS)
    cdir = "/"
    cmd_n = 0

    try:
        # ── Login teaser: reject 2-4 times to build sunk cost ─────────────
        magic = random.randint(2, 4)
        attempt = 1
        login_att = 0
        user = ""
        pw = ""

        while attempt <= magic:
            conn.send(b"\r\nUser Access Verification\r\n\r\nUsername: ")
            user = conn.recv(1024).decode(errors='ignore').strip()
            conn.send(b"Password: ")
            pw = conn.recv(1024).decode(errors='ignore').strip()
            hist.append(f"AUTH_ATTEMPT_{attempt}:{user}/{pw}")

            if attempt < magic:
                login_att += 1
                time.sleep(1.5)
                conn.send(b"\r\n% Login invalid\r\n")
                mqtt_pub({"attacker_ip":ip,"service":"TELNET","action_taken":"AUTH_FAILED",
                          "details":f"Rejected:{user}/{pw}",
                          "state_vector":[len(user+pw),0,1,login_att,0]})
                attempt += 1
            else:
                break

        # Skip brain during login — brain only consulted for shell commands.
        # Calling ask_brain("LOGIN",...) caused WGET_BAIT to appear in logs
        # during the auth phase because "LOGIN" superficially matched threat
        # patterns in the state vector, confusing the reward signal.

        conn.send(b"\r\nBusyBox v1.30.1 (2023-04-01) built-in shell (ash)\r\n")
        conn.send(b"Enter 'help' for a list of built-in commands.\r\n\r\n")

        while True:
            prompt = f"Router:{cdir}# " if cdir != "/" else "Router# "
            conn.send(prompt.encode())

            try:
                cmd = conn.recv(1024).decode(errors='ignore').strip()
            except: break
            if not cmd: continue

            hist.append(f"CMD:{cmd}")
            cmd_n += 1

            base = cmd.split()[0] if cmd.split() else ""
            args = cmd.split()[1:] if len(cmd.split()) > 1 else []

            # exit always works — no brain involvement
            if base in ("exit", "quit", "logout"):
                conn.send(b"\r\n")
                break

            # Ask brain
            pending_actions[ip]["event"].clear()
            ask_brain(ip, cmd, cmd_n, login_att)
            resp = pending_actions[ip]["event"].wait(3.0)
            action_id = pending_actions[ip]["action"] if resp else 0

            if action_id == 0:
                # Normal BusyBox shell
                status, cdir = exec_cmd(conn, cmd, base, args, cdir, fs, fc)
                if status == "REBOOT": break

            elif action_id == 1:
                # Permissions tease
                conn.send(f"ash: {cmd}: Permission denied (root privileges required)\r\n".encode())

            elif action_id == 2:
                # Hardware tarpit
                conn.send(b"Allocating memory... ")
                time.sleep(random.uniform(5.0, 8.0))
                conn.send(b"done\r\nSystem I/O lag detected. Command timed out.\r\n")

            elif action_id == 3:
                # Mirai magnet — wget/curl succeeds
                if base in ("wget", "curl", "tftp", "ftpget"):
                    url = args[-1] if args else "http://unknown"
                    fname = url.split("/")[-1] or "payload"
                    host = url.split("/")[2] if "//" in url else url
                    conn.send(f"Connecting to {host}... connected.\r\n".encode())
                    time.sleep(random.uniform(0.5, 1.5))
                    conn.send(b"HTTP request sent, awaiting response... 200 OK\r\n")
                    sz = random.randint(4000, 9000)
                    conn.send(f"Length: {sz} bytes\r\nSaving to: '{fname}'\r\n".encode())
                    time.sleep(0.3)
                    conn.send(f"{fname}  100%[=====>]  {sz//1024}.{random.randint(1,9)}K  "
                              f"--.-KB/s    in 0.0s\r\n\r\n".encode())
                    if fname not in fs.get(cdir, []): fs[cdir].append(fname)
                    hist.append(f"BOTNET_PAYLOAD:{url}")
                elif base == "chmod":
                    pass
                elif base.startswith("./") or base in ("sh", "bash"):
                    conn.send(b"Segmentation fault\r\n")
                else:
                    status, cdir = exec_cmd(conn, cmd, base, args, cdir, fs, fc)
                    if status == "REBOOT": break

            elif action_id == 4:
                # Config reveal — run command first, then append NVRAM dump
                # Only append for exploration commands, NOT wget/reboot/chmod
                status, cdir = exec_cmd(conn, cmd, base, args, cdir, fs, fc)
                if status == "REBOOT": break
                exploration = ("ls","cat","pwd","id","ps","ifconfig","uname","whoami",
                               "netstat","find","echo","hostname","help")
                if base in exploration:
                    time.sleep(0.4)
                    conn.send(NVRAM_DUMP)

    except: pass
    finally:
        dur = round(time.time()-t0, 2)
        report_end(ip, dur, hist)
        if ip in pending_actions: del pending_actions[ip]
        try: conn.close()
        except: pass


def start_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 2323))
    srv.listen(5)
    print("[*] Telnet Trap on port 2323...")
    while True:
        s, a = srv.accept()
        threading.Thread(target=handle_attacker, args=(s,a), daemon=True).start()

if __name__ == "__main__":
    sys.stdout.reconfigure(line_buffering=True)
    start_server()
