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
    except Exception:
        pass


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
    except Exception:
        pass


def ask_brain(ip, user, pw, cmd, login_att, cmd_n, dl_n):
    mqtt_pub({
        "attacker_ip": ip,
        "service": "FTP",
        "action_taken": "PENDING",
        "details": f"Cmd:{cmd}",
        "state_vector": [len(cmd), login_att, cmd_n, dl_n, cmd_n]
    })


def report_end(ip, dur, hist):
    mqtt_pub({
        "attacker_ip": ip,
        "service": "FTP",
        "action_taken": "SESSION_END",
        "details": " | ".join(hist) if hist else "No commands.",
        "duration": dur,
        "commands_typed": len(hist)
    })


# ── Fake filesystem with directory tree ───────────────────────────────────────
FS_TREE = {
    "/": ["firmware_update_v2.1.bin", "device_config.xml", "api_keys.env",
          "backup_2025-03.tar.gz", "mqtt_credentials.conf", "logs", "configs"],
    "/logs": ["gateway.log", "auth.log", "error.log"],
    "/configs": ["network.conf", "mqtt.conf", "db.conf"],
}

FILE_INFO = {
    "firmware_update_v2.1.bin": 2097152,
    "device_config.xml": 4823,
    "api_keys.env": 512,
    "backup_2025-03.tar.gz": 8388608,
    "mqtt_credentials.conf": 1024,
    "gateway.log": 18432,
    "auth.log": 9216,
    "error.log": 4096,
    "network.conf": 1024,
    "mqtt.conf": 768,
    "db.conf": 512,
}

# Honeytoken file contents
FILE_PAYLOADS = {
    "device_config.xml": (
        b'<?xml version="1.0"?>\n<config>\n'
        b'  <device id="gateway-prod-001" firmware="v2.1.4"/>\n'
        b'  <mqtt host="iot-prod.internal.example.com" port="8883"\n'
        b'        user="iot-gateway-prod" pass="gw_mqtt_s3cr3t!"/>\n'
        b'  <db   host="192.168.10.20" name="iot_prod"\n'
        b'        user="iotadmin"      pass="Pr0d_DB_P@ssw0rd_2025!"/>\n'
        b'  <aws  key="AKIAIOSFODNN7EXAMPLE"\n'
        b'        secret="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
        b'        bucket="iot-backups-prod"/>\n'
        b'</config>\n'
    ),
    "api_keys.env": (
        b"# IoT Gateway API Config\n"
        b"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        b"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        b"AWS_S3_BUCKET=iot-backups-prod\n"
        b"MQTT_PASSWORD=gw_mqtt_s3cr3t!\n"
        b"DB_PASSWORD=Pr0d_DB_P@ssw0rd_2025!\n"
        b"INFLUX_TOKEN=influx_fake_abcdef1234567890abcdef\n"
    ),
    "mqtt_credentials.conf": (
        b"[broker]\n"
        b"host=iot-prod.internal.example.com\nport=8883\ntls=true\n"
        b"username=iot-gateway-prod\npassword=gw_mqtt_s3cr3t!\n\n"
        b"[local_broker]\nhost=192.168.10.50\nport=1883\n"
        b"username=local-gateway\npassword=local_m!tt_2025\n"
    ),
    "gateway.log": (
        b"[2026-04-02 14:00:01] System started\n"
        b"[2026-04-02 14:00:05] MQTT connected to iot-prod.internal.example.com:8883\n"
        b"[2026-04-02 14:01:22] sensor-001 temp=23.4 connected\n"
        b"[2026-04-02 14:20:01] SSH login admin from 192.168.1.50\n"
    ),
    "network.conf": (
        b"[network]\neth0=192.168.10.5/24\ngateway=192.168.10.1\ndns=8.8.8.8\n\n"
        b"[internal]\ndb_host=192.168.10.20\ncam_host=192.168.10.22\n"
        b"cam_pass=cam_r00t!\n"
    ),
}


def handle_attacker(conn, addr):
    ip = addr[0]
    t0 = time.time()
    hist = []
    # Use a mutable dict so the get_data_conn() closure always sees current values
    data = {"port": None, "pasv": None}  # port = (ip,port) tuple; pasv = server socket
    pending_actions[ip] = {"event": threading.Event(), "action": 0}

    def get_data_conn():
        """Open data connection — supports both PORT/EPRT and PASV mode."""
        if data["port"]:
            try:
                ds = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                ds.settimeout(1.5)
                ds.connect(data["port"])
                return ds
            except Exception:
                return None
        elif data["pasv"]:
            try:
                data["pasv"].settimeout(5.0)
                client_ds, _ = data["pasv"].accept()
                client_ds.settimeout(5.0)
                return client_ds
            except Exception:
                return None
        return None

    # Per-session mutable filesystem
    fs = {k: list(v) for k, v in FS_TREE.items()}
    cdir = "/"

    try:
        conn.send(b"220 (vsFTPd 3.0.3)\r\n")

        # ── Login teaser: reject 2-3 times then accept ────────────────────
        magic = random.randint(2, 3)
        attempt = 1
        login_att = 0
        user = "anonymous"
        pw = ""

        while attempt <= magic:
            raw = conn.recv(1024).decode(errors='ignore').strip()
            if not raw:
                break
            hist.append(raw)
            verb = raw.split()[0].upper() if raw.split() else ""

            if verb == "USER":
                user = raw.split(" ", 1)[1] if " " in raw else "anonymous"
                conn.send(b"331 Please specify the password.\r\n")
            elif verb == "PASS":
                pw = raw.split(" ", 1)[1] if " " in raw else ""
                if attempt < magic:
                    login_att += 1
                    time.sleep(1.2)
                    conn.send(b"530 Login incorrect.\r\n")
                    mqtt_pub({
                        "attacker_ip": ip,
                        "service": "FTP",
                        "action_taken": "AUTH_FAILED",
                        "details": f"Rejected:{user}/{pw}",
                        "state_vector": [len(user + pw), login_att, 0, 0, 0]
                    })
                    attempt += 1
                else:
                    break
            elif verb == "QUIT":
                conn.send(b"221 Goodbye.\r\n")
                return
            else:
                conn.send(b"530 Please login with USER and PASS.\r\n")

        # Ask brain for initial action
        ask_brain(ip, user, pw, user + pw, login_att, 0, 0)
        resp = pending_actions[ip]["event"].wait(5.0)
        action_id = pending_actions[ip]["action"] if resp else 0

        # Action 4: LOGIN_REJECTED — Brain decided this attacker gets nothing
        # Used for known scanners or when Brain wants to conserve resources
        if action_id == 4:
            conn.send(b"530 Login incorrect. Account locked.\r\n")
            return  # close session — no command loop

        # All other actions: login succeeds, enter command loop
        conn.send(b"230 Login successful.\r\n")

        cmd_n = 0
        dl_n = 0

        while True:
            raw = conn.recv(1024).decode(errors='ignore').strip()
            if not raw:
                break
            hist.append(raw)
            cmd_n += 1
            parts = raw.split(" ", 1)
            verb = parts[0].upper()
            arg = parts[1].strip() if len(parts) > 1 else ""

            # Re-ask brain on data commands with fresh state
            if verb in ("RETR", "STOR", "LIST", "NLST", "DIR", "DELE", "MKD", "RMD"):
                pending_actions[ip]["event"].clear()
                ask_brain(ip, user, pw, raw, login_att, cmd_n, dl_n)
                resp = pending_actions[ip]["event"].wait(3.0)
                action_id = pending_actions[ip]["action"] if resp else 0

            # ── Standard control commands (always respond) ────────────────
            if verb == "QUIT":
                conn.send(b"221 Goodbye.\r\n")
                break

            elif verb == "SYST":
                conn.send(b"215 UNIX Type: L8\r\n")

            elif verb == "FEAT":
                conn.send(b"211-Features:\r\n PASV\r\n UTF8\r\n SIZE\r\n MDTM\r\n211 End\r\n")

            elif verb in ("TYPE", "OPTS"):
                conn.send(b"200 Command okay.\r\n")

            elif verb == "PWD":
                conn.send(f'257 "{cdir}" is the current directory.\r\n'.encode())

            elif verb == "CWD":
                target = arg if arg.startswith("/") else (cdir.rstrip("/") + "/" + arg).replace("//", "/")
                if target == "/..":
                    target = "/"
                if target in fs:
                    cdir = target
                    conn.send(b"250 Directory successfully changed.\r\n")
                else:
                    conn.send(b"550 Failed to change directory.\r\n")

            elif verb == "CDUP":
                cdir = cdir.rsplit("/", 1)[0] or "/"
                conn.send(b"200 Directory successfully changed.\r\n")

            elif verb == "PORT":
                try:
                    p = arg.split(",")
                    port_ip = ".".join(p[:4])
                    port_num = int(p[4]) * 256 + int(p[5])
                    data["port"] = (port_ip, port_num)
                    if data["pasv"]:
                        try:
                            data["pasv"].close()
                        except:
                            pass
                        data["pasv"] = None
                    conn.send(b"200 PORT command successful.\r\n")
                except Exception:
                    conn.send(b"501 Syntax error.\r\n")

            elif verb == "EPRT":
                try:
                    parts_e = raw.split("|")
                    port_num = int(parts_e[3])
                    data["port"] = (ip, port_num)
                    conn.send(b"200 EPRT command successful.\r\n")
                except Exception:
                    conn.send(b"501 Syntax error.\r\n")

            elif verb == "PASV":
                if data["pasv"]:
                    try:
                        data["pasv"].close()
                    except:
                        pass

                data["pasv"] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                data["pasv"].setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

                pasv_port = 0
                for p in range(2122, 2130):
                    try:
                        data["pasv"].bind(("0.0.0.0", p))
                        pasv_port = p
                        break
                    except Exception:
                        pass

                if pasv_port == 0:
                    conn.send(b"425 Cannot open passive connection.\r\n")
                    continue

                data["pasv"].listen(1)
                data["port"] = None

                p1, p2 = pasv_port >> 8, pasv_port & 0xff
                conn.send(f"227 Entering Passive Mode (127,0,0,1,{p1},{p2}).\r\n".encode())

            elif verb == "SIZE":
                sz = FILE_INFO.get(arg, FILE_INFO.get(arg.split("/")[-1], 1024))
                conn.send(f"213 {sz}\r\n".encode())

            elif verb == "MDTM":
                conn.send(b"213 20260402142200\r\n")

            elif verb == "MKD":
                dirname = arg if arg.startswith("/") else cdir.rstrip("/") + "/" + arg
                fs[dirname] = []
                fs[cdir].append(arg)
                conn.send(f'257 "{dirname}" created.\r\n'.encode())

            elif verb == "RMD":
                target = arg if arg.startswith("/") else cdir.rstrip("/") + "/" + arg
                if target in fs:
                    del fs[target]
                    if arg in fs.get(cdir, []):
                        fs[cdir].remove(arg)
                conn.send(b"250 Remove directory operation successful.\r\n")

            elif verb == "DELE":
                fname = arg.split("/")[-1]
                if fname in fs.get(cdir, []):
                    fs[cdir].remove(fname)
                conn.send(b"250 Delete operation successful.\r\n")
                hist.append(f"DELETED:{arg}")

            elif verb == "RNFR":
                conn.send(b"350 Ready for RNTO.\r\n")

            elif verb == "RNTO":
                conn.send(b"250 Rename successful.\r\n")

            elif verb in ("LIST", "NLST", "DIR"):
                if action_id == 2:  # Slow-drip tarpit
                    conn.send(b"150 Opening data connection...\r\n")
                    ds = get_data_conn()
                    if ds:
                        for _ in range(4):
                            time.sleep(30)
                            try:
                                ds.send(b".")
                            except:
                                break
                        try:
                            ds.close()
                        except:
                            pass
                    conn.send(b"425 Data connection timed out.\r\n")
                else:
                    d = arg.strip() if arg.strip() and arg.strip() in fs else cdir
                    conn.send(b"150 Here comes the directory listing.\r\n")
                    ds = get_data_conn()
                    if ds:
                        try:
                            listing = ""
                            for f in fs.get(d, []):
                                is_dir = (d.rstrip("/") + "/" + f) in fs or f in fs
                                perm = "drwxr-xr-x" if is_dir else "-rw-r--r--"
                                sz = FILE_INFO.get(f, 1024)
                                listing += f"{perm} 1 ftp ftp {sz:8d} Apr 02 14:22 {f}\r\n"
                            ds.send(listing.encode() if listing else b"\r\n")
                            ds.close()
                            conn.send(b"226 Directory send OK.\r\n")
                        except Exception:
                            try:
                                ds.close()
                            except:
                                pass
                            conn.send(b"426 Connection closed; transfer aborted.\r\n")
                    else:
                        conn.send(b"425 Can't open data connection. Use PORT or PASV.\r\n")

            elif verb == "RETR":
                fname = arg.split("/")[-1]
                if action_id == 2:
                    conn.send(b"150 Opening BINARY mode data connection...\r\n")
                    ds = get_data_conn()
                    if ds:
                        payload = FILE_PAYLOADS.get(fname, b"BINARY_DATA")
                        try:
                            ds.send(payload[:1])
                            time.sleep(30)
                            if len(payload) > 1:
                                ds.send(payload[1:2])
                            time.sleep(30)
                            ds.close()
                        except Exception:
                            pass
                    conn.send(b"425 Data connection timed out.\r\n")
                elif action_id in (0, 1):
                    conn.send(b"150 Opening BINARY mode data connection.\r\n")
                    ds = get_data_conn()
                    if ds:
                        try:
                            payload = FILE_PAYLOADS.get(fname, b"FAKE_BINARY_DATA\x00\x01\x02\x03")
                            ds.send(payload)
                            ds.close()
                            conn.send(b"226 Transfer complete.\r\n")
                            dl_n += 1
                            hist.append(f"DOWNLOADED:{fname}")
                        except Exception:
                            try:
                                ds.close()
                            except:
                                pass
                            conn.send(b"426 Connection closed; transfer aborted.\r\n")
                    else:
                        conn.send(b"425 Can't open data connection.\r\n")
                else:
                    conn.send(b"550 Permission denied.\r\n")

            elif verb == "STOR":
                fname = arg.split("/")[-1]
                # Action 3: FAKE_STOR_ACCEPT — accept upload, capture payload silently
                # Action 0/1/default: also accept (any action = let them upload)
                # The difference: action 3 is when Brain specifically wants to lure
                # the attacker into uploading their malware after they downloaded honeytokens
                if action_id == 4:
                    # Brain decided to reject at login, but if they somehow get here, block
                    conn.send(b"550 Permission denied.\r\n")
                elif action_id == 2:
                    # Tarpit the upload — accept connection but hang it
                    conn.send(b"150 Ok to send data.\r\n")
                    ds = get_data_conn()
                    if ds:
                        try:
                            time.sleep(30)  # freeze their upload for 30s
                            ds.close()
                        except: pass
                    conn.send(b"426 Connection closed; transfer aborted.\r\n")
                else:
                    # Actions 0, 1, 3 — all accept the upload
                    # Action 3 specifically = Brain is targeting this attacker for malware capture
                    conn.send(b"150 Ok to send data.\r\n")
                    ds = get_data_conn()
                    if ds:
                        try:
                            chunks = []
                            while True:
                                d_chunk = ds.recv(8192)
                                if not d_chunk: break
                                chunks.append(d_chunk)
                            received = b"".join(chunks)
                            ds.close()
                            if fname not in fs.get(cdir, []):
                                fs[cdir].append(fname)
                            conn.send(b"226 Transfer complete.\r\n")
                            tag = "MALWARE_CAPTURED" if action_id == 3 else "UPLOAD_CAPTURED"
                            hist.append(f"{tag}:{fname}:{len(received)}bytes")
                        except Exception:
                            try: ds.close()
                            except: pass
                            conn.send(b"426 Connection closed; transfer aborted.\r\n")
                    else:
                        conn.send(b"425 Can't open data connection.\r\n")

            elif verb == "APPE":
                conn.send(b"150 Ok to send data.\r\n")
                ds = get_data_conn()
                if ds:
                    try:
                        data_recv = ds.recv(65536)
                        ds.close()
                        conn.send(b"226 Transfer complete.\r\n")
                    except Exception:
                        conn.send(b"426 Transfer aborted.\r\n")
                else:
                    conn.send(b"425 Can't open data connection.\r\n")

            elif verb == "NOOP":
                conn.send(b"200 NOOP ok.\r\n")

            elif verb == "STAT":
                conn.send(b"211-FTP server status:\r\n Connected.\r\n211 End of status.\r\n")

            else:
                conn.send(b"500 Unknown command.\r\n")

    except Exception:
        pass
    finally:
        dur = round(time.time() - t0, 2)
        report_end(ip, dur, hist)
        if ip in pending_actions:
            del pending_actions[ip]
        if data["pasv"]:
            try:
                data["pasv"].close()
            except Exception:
                pass
        try:
            conn.close()
        except Exception:
            pass


def start_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 2121))
    srv.listen(5)
    print("[*] FTP Trap on port 2121...")
    while True:
        s, a = srv.accept()
        threading.Thread(target=handle_attacker, args=(s, a), daemon=True).start()


if __name__ == "__main__":
    sys.stdout.reconfigure(line_buffering=True)
    start_server()
