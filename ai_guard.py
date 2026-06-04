import paho.mqtt.client as mqtt
import json
import torch
import torch.nn as nn
import torch.optim as optim
import os
import sys
import pymongo
import random
import numpy as np
from collections import deque, defaultdict
from datetime import datetime

MONGO_ADDR  = os.getenv("MONGO_ADDR", "mongodb")
MQTT_BROKER = os.getenv("MQTT_BROKER_ADDR", "mqtt_broker")

# ─── TRUE DQN HYPERPARAMETERS ────────────────────────────────────────
GAMMA = 0.95           # Discount factor for future rewards
LR = 0.001             # Learning rate
BATCH_SIZE = 64        # Samples per training step
BUFFER_SIZE = 10000    # Replay buffer capacity
TARGET_UPDATE = 200    # Update target network every N steps
EPSILON_START = 0.15   # 15% Exploration (since we pre-trained)
EPSILON_END = 0.05     # Minimum 5% exploration forever
EPSILON_DECAY = 0.995

# ─────────────────────────────────────────────────────────────
ACTION_MAPS = {
    "SSH": {0: "LIMITED_SHELL", 1: "FULL_SHELL", 2: "FAKE_SUDO", 3: "HONEYTOKEN_EXPOSE", 4: "TARPIT", 5: "CONTROLLED_FAIL"},
    "HTTP": {0: "LIVE_DASHBOARD", 1: "FAKE_ADMIN_PANEL", 2: "WAF_BLOCK_403", 3: "TARPIT", 4: "CAPTCHA_RATELIMIT"},
    "FTP": {0: "FAKE_FILESYSTEM", 1: "HONEYTOKEN_RETR", 2: "TARPIT_DATA_CONN", 3: "FAKE_STOR_ACCEPT", 4: "LOGIN_REJECTED"},
    "TELNET": {0: "BUSYBOX_SHELL", 1: "INVALID_LOOP", 2: "TARPIT", 3: "WGET_BAIT", 4: "CONFIG_REVEAL"},
}

MODEL_CFG = {
    "SSH":    ("ssh_dqn.pth",    6),
    "HTTP":   ("http_dqn.pth",   5),
    "FTP":    ("ftp_dqn.pth",    5),
    "TELNET": ("telnet_dqn.pth", 5),
}

# ─── NEURAL NETWORK ──────────────────────────────────────────────────
class DQN(nn.Module):
    def __init__(self, n_actions):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(5, 64), nn.ReLU(),
            nn.Linear(64, 64), nn.ReLU(),
            nn.Linear(64, n_actions)
        )
    def forward(self, x):
        return self.net(x)

# ─── AGENT CLASS (Manages Target Networks & Memory) ──────────────────
class DQNAgent:
    def __init__(self, service, n_act, model_file):
        self.service = service
        self.model_file = model_file
        self.policy_net = DQN(n_act)
        self.target_net = DQN(n_act)
        
        # Load Pre-trained weights!
        if os.path.exists(model_file):
            self.policy_net.load_state_dict(torch.load(model_file, map_location="cpu", weights_only=True))
            print(f"[OK] {service:6s} pre-trained weights loaded.")
        
        self.target_net.load_state_dict(self.policy_net.state_dict())
        self.target_net.eval()
        self.policy_net.train()
        
        self.optimizer = optim.Adam(self.policy_net.parameters(), lr=LR)
        self.buffer = deque(maxlen=BUFFER_SIZE)
        self.epsilon = EPSILON_START
        self.steps = 0

    def push(self, state, action, reward, next_state, done):
        self.buffer.append((state, action, reward, next_state, done))

    def train_step(self):
        if len(self.buffer) < BATCH_SIZE: return
        
        batch = random.sample(self.buffer, BATCH_SIZE)
        states, actions, rewards, next_states, dones = zip(*batch)

        states = torch.tensor(np.array(states), dtype=torch.float32)
        actions = torch.tensor(actions, dtype=torch.long).unsqueeze(1)
        rewards = torch.tensor(rewards, dtype=torch.float32)
        next_states = torch.tensor(np.array(next_states), dtype=torch.float32)
        dones = torch.tensor(dones, dtype=torch.float32)

        # Current Q
        current_q = self.policy_net(states).gather(1, actions).squeeze(1)
        # Target Q (using frozen Target Net)
        with torch.no_grad():
            max_next_q = self.target_net(next_states).max(1)[0]
            target_q = rewards + (GAMMA * max_next_q * (1 - dones))

        loss = nn.MSELoss()(current_q, target_q)
        self.optimizer.zero_grad()
        loss.backward()
        nn.utils.clip_grad_norm_(self.policy_net.parameters(), 1.0)
        self.optimizer.step()

        self.steps += 1
        self.epsilon = max(EPSILON_END, self.epsilon * EPSILON_DECAY)

        # Sync target network
        if self.steps % TARGET_UPDATE == 0:
            self.target_net.load_state_dict(self.policy_net.state_dict())
            torch.save(self.policy_net.state_dict(), self.model_file)

agents = {svc: DQNAgent(svc, n_act, path) for svc, (path, n_act) in MODEL_CFG.items()}

# ─── MONGODB & TRACKING ──────────────────────────────────────────────
try:
    _mc = pymongo.MongoClient(f"mongodb://{MONGO_ADDR}:27017/")
    attacks_col = _mc["honeypot_db"]["attacks"]
    print(f"[OK] MongoDB connected at {MONGO_ADDR}")
except Exception as e:
    attacks_col = None

ip_mem = defaultdict(lambda: {"total_sessions": 0, "total_commands": 0, "classified_as": "unknown"})
active_sessions = defaultdict(dict)   # key = (ip, service)

def classify(ip):
    m = ip_mem[ip]
    cps = m["total_commands"] / max(m["total_sessions"], 1)
    if m["total_sessions"] > 5 and cps < 4: return "botnet_scanner"
    if m["total_commands"] > 15: return "manual_attacker"
    return "unknown"

# ─── REWARD FUNCTION ─────────────────────────────────────────────────
def compute_reward(service, action_id, session_dur, cmds=0, is_terminal=False):
    if is_terminal:
        # Terminal: reward proportional to how long we kept the attacker
        time_r = session_dur / 60.0
        # Bonus for deep engagement (more commands = more intel gathered)
        depth_r = min(cmds / 10.0, 2.0)
        return time_r + depth_r
    # Non-terminal: small shaping reward scaled by engagement depth
    return 0.05 + min(cmds * 0.02, 0.3)

# ─── LIVE MQTT ROUTER ────────────────────────────────────────────────
def on_message(client, userdata, msg):
    try:
        data = json.loads(msg.payload.decode())
        ip = data.get("attacker_ip", "Unknown")
        service = data.get("service", "").upper()
        action_taken = data.get("action_taken", "")
        if service not in agents: return

        agent = agents[service]

        # ── 1. SESSION END: Calculate Terminal Reward & Train ──
        if action_taken == "SESSION_END":
            duration = data.get("duration", 0)
            cmds = data.get("commands_typed", 0)
            ip_mem[ip]["total_sessions"] += 1
            ip_mem[ip]["total_commands"] += cmds
            ip_mem[ip]["classified_as"] = classify(ip)

            sess_key = (ip, service)
            reward = compute_reward(service, 0, float(duration), cmds=cmds, is_terminal=True)
            print(f"[END]  {service:6s} | {ip:15s} | Reward: +{reward:.2f} | dur={duration}s cmds={cmds}")

            if sess_key in active_sessions and "prev_state" in active_sessions[sess_key]:
                prev_st = active_sessions[sess_key]["prev_state"]
                prev_act = active_sessions[sess_key]["prev_action"]
                # Push terminal state
                agent.push(prev_st, prev_act, reward, [0]*5, 1.0)
                agent.train_step()
                del active_sessions[sess_key]
            return

        # ── 2. ACTIVE ATTACK: Epsilon-Greedy Choice ──
        sv = (data.get("state_vector", []) + [0, 0, 0, 0, 0])[:5]
        sess_key = (ip, service)

        # Push previous step to memory (non-terminal)
        if sess_key in active_sessions and "prev_state" in active_sessions[sess_key]:
            eng_depth = sv[2]  # cmd_count from state vector
            step_reward = compute_reward(service, active_sessions[sess_key]["prev_action"], 0, cmds=eng_depth)
            agent.push(active_sessions[sess_key]["prev_state"], active_sessions[sess_key]["prev_action"], step_reward, sv, 0.0)
            agent.train_step()

        # Epsilon Greedy
        if random.random() < agent.epsilon:
            action_id = random.randint(0, MODEL_CFG[service][1] - 1)
            exploring = True
        else:
            with torch.no_grad():
                q = agent.policy_net(torch.tensor(sv, dtype=torch.float32).unsqueeze(0))
                action_id = int(torch.argmax(q).item())
            exploring = False

        action_text = ACTION_MAPS[service].get(action_id, "UNKNOWN")
        tag = "[EXP]" if exploring else "[ACT]"
        print(f"{tag}  {service:6s} | {ip:15s} | act={action_id} ({action_text:20s}) | eps={agent.epsilon:.3f}")

        # Save state for next step's Bellman calculation — keyed by (ip, service)
        active_sessions[sess_key] = {"prev_state": sv, "prev_action": action_id}

        client.publish(f"honeypot/actions/{ip}", json.dumps({"action_id": action_id, "service": service}))

        if attacks_col is not None:
            attacks_col.insert_one({"timestamp": datetime.now(), "attacker_ip": ip, "service": service, "action_taken": action_text, "attacker_type": ip_mem[ip]["classified_as"]})

    except Exception as e:
        print(f"[ERR]  on_message: {e}")

# ─── STARTUP ─────────────────────────────────────────────────────────
mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
mqtt_client.on_message = on_message
mqtt_client.connect(MQTT_BROKER, 1883, 60)
mqtt_client.subscribe("honeypot/alerts")
sys.stdout.reconfigure(line_buffering=True)
print("[*] TRUE DQN Brain Online. Target Networks & Live Learning enabled.")
mqtt_client.loop_forever()
