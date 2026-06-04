import time
import socket
import paramiko
import threading
import paho.mqtt.client as mqtt
import json
import os
import sys
import random

MQTT_BROKER = os.getenv("MQTT_BROKER_ADDR", "mqtt_broker")
MQTT_TOPIC_ALERTS = "honeypot/alerts"
MQTT_TOPIC_ACTIONS = "honeypot/actions/+"
HOST_KEY = paramiko.RSAKey.generate(2048)

pending_actions = {}
ip_mem = {}

def get_mem(ip):
    if ip not in ip_mem:
        ip_mem[ip] = {"sessions": 0, "commands": 0, "classified": "unknown"}
    return ip_mem[ip]

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

def ask_brain(ip, cmd, n, sudo_n=0):
    hi = ["wget","curl","rm","chmod","python","perl","bash","sh","nc","ncat","dd","mkfs"]
    t = 5 if any(cmd.startswith(x) for x in hi) else 1
    mqtt_pub({"attacker_ip":ip,"service":"SSH","action_taken":"PENDING",
              "details":f"Typed:{cmd}","state_vector":[len(cmd),n,t,n,sudo_n]})

def report_end(ip, dur, hist):
    mqtt_pub({"attacker_ip":ip,"service":"SSH","action_taken":"SESSION_END",
              "details":" | ".join(hist) if hist else "No commands.",
              "duration":dur,"commands_typed":len(hist)})

class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self, ip, hist):
        self.ip = ip; self.hist = hist; self.event = threading.Event()
        self.creds = ""; self.attempts = 0
        # KEY FIX: 1-2 attempts max so SSH client (MaxAuthTries=3) never closes us
        self.magic = random.randint(1, 2)

    def check_auth_password(self, user, pw):
        self.attempts += 1
        self.creds = f"{user}/{pw}"
        self.hist.append(f"AUTH_ATTEMPT_{self.attempts}: {self.creds}")
        if self.attempts < self.magic:
            time.sleep(1.5)
            mqtt_pub({"attacker_ip":self.ip,"service":"SSH","action_taken":"AUTH_FAILED",
                      "details":f"Rejected:{self.creds}","state_vector":[len(user+pw),0,1,0,0]})
            return paramiko.AUTH_FAILED
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, u): return 'password'
    def check_channel_request(self, k, c):
        return paramiko.OPEN_SUCCEEDED if k=='session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    def check_channel_pty_request(self,c,t,w,h,pw,ph,m): return True
    def check_channel_shell_request(self, ch): self.event.set(); return True

FS_BASE = {
    "/":["bin","etc","home","var","tmp","root","opt","proc"],
    "/root":["device_config.yaml","api_keys.env","backup_2025.tar.gz",".bash_history",".aws"],
    "/root/.aws":["credentials","config"],
    "/etc":["passwd","shadow","crontab","hosts","mqtt.conf"],
    "/etc/ssh":["sshd_config","id_rsa","id_rsa.pub"],
    "/var":["log","www","run"],
    "/var/log":["auth.log","syslog","mqtt.log"],
    "/tmp":[],
    "/home":["admin","ubuntu"],
    "/opt":["iot-gateway","scripts"],
    "/opt/iot-gateway":["gateway","config.yaml","start.sh","healthcheck.sh","logs"],
    "/opt/iot-gateway/logs":["gateway.log","error.log"],
    "/proc":["cpuinfo","meminfo","version"],
}

FC = {
    "/etc/passwd":(b"root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:IoT Admin:/home/admin:/bin/bash\n"
                   b"ubuntu:x:1001:1001::/home/ubuntu:/bin/bash\nmqtt:x:1002:1002::/opt/iot-gateway:/bin/sh\n"),
    "/etc/shadow":(b"root:$6$rounds=656000$fakesalt0root$VeryLongFakeHashThatLooksRealButLeadsNowhere"
                   b"00000000000000000000000000000000000000000000000:19800:0:99999:7:::\n"
                   b"admin:$6$rounds=656000$fakesalt0adm$AnotherFakeHashWillWasteYourGPUForWeeks"
                   b"000000000000000000000000000000000000000000000:19800:0:99999:7:::\n"),
    "/root/api_keys.env":(b"# IoT Gateway API Config - DO NOT COMMIT\n"
                          b"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
                          b"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
                          b"DB_PASSWORD=Pr0d_DB_P@ssw0rd_2025!\nMQTT_PASSWORD=Mqtt_Pr0d_2025!\n"
                          b"INFLUX_TOKEN=influx_fake_abcdef1234567890abcdef1234567890\n"),
    "/root/.aws/credentials":(b"[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
                               b"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n\n"
                               b"[production]\naws_access_key_id = AKIAI44QH8DHBEXAMPLE\n"
                               b"aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY\n"),
    "/etc/ssh/id_rsa":(b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4PAt\n"
                       b"fakePrivateKeyDataThatLooksRealButIsUseless000000000000000000000000\n"
                       b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
                       b"-----END RSA PRIVATE KEY-----\n"),
    "/root/device_config.yaml":(b"device_id: gateway-prod-001\nfirmware: v2.1.4\n"
                                 b"mqtt:\n  host: 192.168.10.50\n  port: 1883\n"
                                 b"  username: iot-gateway\n  password: Mqtt_Pr0d_2025!\n"
                                 b"db:\n  host: 192.168.10.20\n  password: Pr0d_DB_P@ssw0rd_2025!\n"),
    "/opt/iot-gateway/config.yaml":(b"broker: iot-prod.internal.example.com\nport: 8883\n"
                                     b"username: iot-gateway-prod\npassword: gw_mqtt_s3cr3t!\n"),
    "/root/.bash_history":(b"ls /etc/\ncat /etc/passwd\ncat /root/api_keys.env\n"
                            b"cat /root/.aws/credentials\nnano /root/device_config.yaml\n"
                            b"aws s3 cp backup_2025.tar.gz s3://iot-backups-prod/\n"),
    "/var/log/auth.log":(b"Apr  2 14:20:01 gateway sshd[1234]: Accepted password for admin from 192.168.1.50\n"
                          b"Apr  2 14:22:09 gateway sudo: admin : USER=root ; COMMAND=/bin/bash\n"),
    "/var/log/mqtt.log":(b"[2026-04-02 14:00:05] CONNECT client=cam-002 pass=Mqtt_Pr0d_2025!\n"
                          b"[2026-04-02 14:00:01] PUBLISH topic=iot/devices/sensor-001/temp payload=23.4\n"),
    "/etc/crontab":(b"*/5 * * * * root /opt/iot-gateway/healthcheck.sh\n"
                    b"0 2 * * * root tar -czf /root/backup_2025.tar.gz /opt/iot-gateway/\n"
                    b"@reboot root /opt/iot-gateway/start.sh\n"),
    "/proc/cpuinfo":(b"processor\t: 0\nmodel name\t: ARMv7 Processor rev 4 (v7l)\nhardware\t: IoT-Gateway-v2\n"),
    "/proc/version":(b"Linux version 5.15.0-58-generic (gcc 11.3.0) #64-Ubuntu SMP\n"),
}

def handle_connection(client_socket, client_addr):
    ip = client_addr[0]
    transport = paramiko.Transport(client_socket)
    transport.add_server_key(HOST_KEY)
    hist = []
    server = FakeSSHServer(ip, hist)
    pending_actions[ip] = {"event": threading.Event(), "action": 0}

    try:
        transport.start_server(server=server)
    except: return
    ch = transport.accept(20)
    if ch is None: return
    server.event.wait(10)
    if not server.event.is_set(): return

    t0 = time.time()
    mem = get_mem(ip)
    mem["sessions"] += 1
    scanner = mem["classified"] == "botnet_scanner"

    # IoT BusyBox banner
    ch.send(b"\r\nBusyBox v1.30.1 built-in shell (ash)\r\n")
    ch.send(b"IoT-Gateway-Prod | Uptime: 14d 6:22 | Load: 0.12\r\n\r\n")

    fs = {k: list(v) for k, v in FS_BASE.items()}
    fc = dict(FC)
    cmd_hist = []
    n = 0
    cdir = "/root"
    user = "admin"    # low-priv to encourage sudo attempts
    sudo_n = 0

    try:
        while True:
            prompt = f"{user}@iot-gateway:{'~' if cdir=='/root' else cdir}$ "
            ch.send(prompt.encode())
            cmd = ""; hidx = len(cmd_hist)

            while True:
                c = ch.recv(1)
                if not c: cmd = "exit"; break
                if c == b'\r':
                    ch.send(b"\r\n")
                    if cmd.strip(): cmd_hist.append(cmd.strip())
                    break
                elif c in (b'\x7f', b'\x08'):
                    if cmd: cmd = cmd[:-1]; ch.send(b'\x08 \x08')
                elif c == b'\x03':
                    ch.send(b"^C\r\n"); cmd = ""; break
                elif c == b'\x1b':
                    sq = ch.recv(2)
                    if sq == b'[A' and hidx > 0:
                        hidx -= 1; ch.send(b'\x1b[2K\r' + prompt.encode())
                        cmd = cmd_hist[hidx]; ch.send(cmd.encode())
                    elif sq == b'[B' and hidx < len(cmd_hist)-1:
                        hidx += 1; ch.send(b'\x1b[2K\r' + prompt.encode())
                        cmd = cmd_hist[hidx]; ch.send(cmd.encode())
                else:
                    try: cmd += c.decode('utf-8'); ch.send(c)
                    except: pass

            s = cmd.strip()
            if not s: continue
            hist.append(f"CMD:{s}")
            n += 1; mem["commands"] += 1
            if s.startswith("sudo"): sudo_n += 1

            # Scanner tarpit — simulate slow IoT CPU
            if scanner:
                ch.send(b"Processing... ")
                time.sleep(15)
                ch.send(b"done\r\n")
                continue

            pending_actions[ip]["event"].clear()
            ask_brain(ip, s, n, sudo_n)
            ok = pending_actions[ip]["event"].wait(3.0)
            act = pending_actions[ip]["action"] if ok else 0

            def run(dangerous=True):
                nonlocal cdir, user
                base = s.split()[0] if s.split() else ""
                args = s.split()[1:] if len(s.split()) > 1 else []

                if base in ("exit","logout","quit"):
                    ch.send(b"logout\r\n"); return "EXIT"
                elif base == "clear": ch.send(b"\x1b[2J\x1b[H")
                elif base == "whoami": ch.send(f"{user}\r\n".encode())
                elif base == "id":
                    uid = "0" if user=="root" else "1000"
                    ch.send(f"uid={uid}({user}) gid={uid}({user}) groups={uid}({user})\r\n".encode())
                elif base == "pwd": ch.send(f"{cdir}\r\n".encode())
                elif base == "hostname": ch.send(b"iot-gateway-prod\r\n")
                elif base == "uname":
                    if "-a" in s: ch.send(b"Linux iot-gateway-prod 5.15.0-58-generic x86_64 GNU/Linux\r\n")
                    else: ch.send(b"Linux\r\n")
                elif base == "cd":
                    t = args[0] if args else "/root"
                    if t == "~": t = "/root"
                    elif t == "..": t = cdir.rsplit("/",1)[0] or "/"
                    elif not t.startswith("/"): t = cdir.rstrip("/") + "/" + t
                    if t in fs: cdir = t
                    else: ch.send(f"ash: cd: {t}: No such file or directory\r\n".encode())
                elif base == "ls":
                    d = cdir
                    for a in args:
                        if not a.startswith("-") and a in fs: d = a
                    if d in fs:
                        if any(f in s for f in ["-l","-la","-al","-a"]):
                            out = "total 64\r\n"
                            for f in fs[d]:
                                p = "drwxr-xr-x" if f in fs else "-rw-r--r--"
                                out += f"{p} 1 root root {random.randint(512,65536):6d} Apr  2 14:22 {f}\r\n"
                        else: out = "  ".join(fs[d]) + "\r\n"
                        ch.send(out.encode())
                    else: ch.send(f"ls: cannot access '{d}': No such file or directory\r\n".encode())
                elif base == "cat":
                    req = args[0] if args else ""
                    fp = req if req.startswith("/") else cdir.rstrip("/") + "/" + req
                    if fp in fc: ch.send(fc[fp]); ch.send(b"\r\n")
                    else: ch.send(f"cat: {req}: No such file or directory\r\n".encode())
                elif base in ("wget","curl"):
                    if dangerous:
                        url = args[-1] if args else "http://unknown"
                        fname = url.split("/")[-1] or "output"
                        ch.send(f"--{time.strftime('%Y-%m-%d %H:%M:%S')}--  {url}\r\n".encode())
                        ch.send(b"Resolving host... connected.\r\n")
                        time.sleep(random.uniform(0.5,1.5))
                        ch.send(b"HTTP request sent... 200 OK\r\n")
                        ch.send(f"Saving to: '{fname}'\n{fname}  100%[=====>]  4.28K  in 0.1s\r\n".encode())
                        fs[cdir].append(fname)
                    else: ch.send(f"ash: {base}: Permission denied\r\n".encode())
                elif base == "chmod": pass
                elif base.startswith("./") or base in ("sh","bash"):
                    if dangerous: time.sleep(0.3); ch.send(b"Segmentation fault (core dumped)\r\n")
                    else: ch.send(f"ash: {base}: Permission denied\r\n".encode())
                elif base == "ps":
                    ch.send(b"  PID USER  STAT VSZ COMMAND\r\n"
                            b"    1 root  S   1548 /sbin/init\r\n"
                            b"  412 root  S   4096 /usr/sbin/sshd\r\n"
                            b"  501 root  S   8192 /opt/iot-gateway/gateway\r\n"
                            b"  889 root  S   2048 mosquitto\r\n")
                elif base in ("ifconfig","ip"):
                    ch.send(b"eth0: inet 192.168.10.5 netmask 255.255.255.0\r\n"
                            b"      ether 02:42:c0:a8:0a:05\r\n")
                elif base == "netstat":
                    ch.send(b"tcp 0 0 0.0.0.0:22  0.0.0.0:* LISTEN\r\n"
                            b"tcp 0 0 0.0.0.0:1883 0.0.0.0:* LISTEN\r\n"
                            b"tcp 0 0 0.0.0.0:80  0.0.0.0:* LISTEN\r\n")
                elif base in ("find","locate"):
                    ch.send(b"/root/api_keys.env\r\n/root/.aws/credentials\r\n"
                            b"/opt/iot-gateway/config.yaml\r\n/etc/shadow\r\n")
                elif base in ("mkdir","mkfifo"):
                    dname = args[0] if args else "newdir"
                    full = cdir.rstrip("/") + "/" + dname
                    fs[full] = []
                    if dname not in fs.get(cdir, []): fs[cdir].append(dname)
                elif base in ("rmdir","rm"):
                    fname = args[-1].split("/")[-1] if args else ""
                    if fname in fs.get(cdir, []): fs[cdir].remove(fname)
                elif base in ("touch","nano","vi","vim"):
                    fname = args[0] if args else "file.txt"
                    bname = fname.split("/")[-1]
                    if bname not in fs.get(cdir, []): fs[cdir].append(bname)
                elif base in ("echo",):
                    # echo "text" > file  or just echo text
                    if ">" in s:
                        text_part = s.split(">")[0].replace("echo","").strip().strip('"\'')
                        fname = s.split(">")[-1].strip()
                        bname = fname.split("/")[-1]
                        if bname not in fs.get(cdir, []): fs[cdir].append(bname)
                    else:
                        ch.send((" ".join(args) + "\r\n").encode())
                elif base == "sudo": pass  # handled by action 2
                elif base == "help":
                    ch.send(b"cd ls cat pwd whoami id ps ifconfig netstat find mkdir rm "
                            b"touch echo wget curl chmod sudo\r\n")
                else:
                    ch.send(f"ash: {base}: command not found\r\n".encode())
                return "OK"

            # ── Actions ────────────────────────────────────────────────────
            if act == 0:           # Limited shell
                if run(dangerous=False) == "EXIT": break

            elif act == 1:         # Full shell
                if run(dangerous=True) == "EXIT": break

            elif act == 2:         # Fake sudo trap — keep looping
                if s.startswith("sudo"):
                    # Extract the actual command being sudo'd
                    sudo_cmd = s[4:].strip()  # everything after "sudo"
                    sudo_base = sudo_cmd.split()[0] if sudo_cmd.split() else ""

                    # Show the sudo password prompt loop
                    for _ in range(2):
                        ch.send(f"[sudo] password for {user}: ".encode())
                        c2 = b""
                        while c2 != b'\r': c2 = ch.recv(1)
                        ch.send(b"\r\n"); time.sleep(1.5)
                        ch.send(b"Sorry, try again.\r\n")
                    ch.send(f"[sudo] password for {user}: ".encode())
                    c2 = b""
                    while c2 != b'\r': c2 = ch.recv(1)
                    ch.send(b"\r\n"); time.sleep(1.5)

                    # After 2+ sudo failures, let the sudo'd command through
                    # This is the "sunk cost" payoff — attacker feels they cracked it
                    if sudo_n >= 2 and sudo_base in ("wget","curl","sh","bash","su","python","perl"):
                        ch.send(b"[sudo] access granted\r\n")
                        time.sleep(0.5)
                        if sudo_base in ("wget","curl"):
                            sudo_args = sudo_cmd.split()[1:]
                            url = sudo_args[-1] if sudo_args else "http://unknown"
                            fname = url.split("/")[-1] or "output"
                            ch.send(f"--{time.strftime('%Y-%m-%d %H:%M:%S')}--  {url}\r\n".encode())
                            ch.send(b"Resolving host... connected.\r\n")
                            time.sleep(random.uniform(0.5, 1.5))
                            ch.send(b"HTTP request sent... 200 OK\r\n")
                            ch.send(f"Saving to: '{fname}'\r\n{fname}  100%[=====>]  4.28K  in 0.1s\r\n".encode())
                            fs[cdir].append(fname)
                        elif sudo_base in ("su","bash","sh"):
                            user = "root"
                            ch.send(b"root@iot-gateway:~# \r\n")
                        else:
                            ch.send(f"[sudo] {sudo_cmd}: executed\r\n".encode())
                    else:
                        ch.send(f"sudo: {sudo_n} incorrect password attempts\r\n".encode())
                else:
                    # Non-sudo command during sudo-trap phase — run limited shell
                    if run(dangerous=False) == "EXIT": break

            elif act == 3:         # Honeytoken exposure
                # Inject extra tempting files into current dir
                for f in ["id_rsa",".aws","credentials.bak"]:
                    if f not in fs.get(cdir, []):
                        fs[cdir].append(f)
                fc[cdir+"/id_rsa"] = fc["/etc/ssh/id_rsa"]
                fc[cdir+"/credentials.bak"] = fc["/root/.aws/credentials"]
                if run(dangerous=True) == "EXIT": break

            elif act == 4:         # Tarpit
                ch.send(b"Processing... ")
                time.sleep(random.uniform(5.0, 8.0))
                ch.send(b"Disk I/O timeout. Please retry.\r\n")

            elif act == 5:         # Controlled failure
                ch.send(f"ash: {s}: Permission denied (SELinux enforcing)\r\n".encode())

    except: pass
    finally:
        duration = round(time.time()-t0, 2)
        report_end(ip, duration, hist)
        if ip in pending_actions: del pending_actions[ip]
        try: ch.close()
        except: pass

def start_honeypot():
    sys.stdout.reconfigure(line_buffering=True)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 2222))
    srv.listen(100)
    print("[*] SSH Honeypot on port 2222...")
    while True:
        s, a = srv.accept()
        threading.Thread(target=handle_connection, args=(s, a), daemon=True).start()

if __name__ == "__main__":
    start_honeypot()
