import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
import random
import pymongo
import time
import argparse
import os
from collections import deque
from datetime import datetime

# ── Configuration ──────────────────────────────────────────────────────────────
MONGO_URI   = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
GAMMA       = 0.95       # discount factor — how much future rewards matter
LR          = 0.001      # learning rate
BATCH_SIZE  = 64         # samples per training step
BUFFER_SIZE = 10000      # replay buffer capacity
TARGET_UPDATE = 200      # update target network every N steps
EPSILON_START = 1.0      # 100% random at start
EPSILON_END   = 0.05     # minimum 5% random forever
EPSILON_DECAY = 0.995    # multiply epsilon by this each episode
BOOTSTRAP_EPISODES = 3000  # synthetic episodes before live training

# ── Per-service configuration ─────────────────────────────────────────────────
SERVICE_CFG = {
    "SSH": {
        "n_actions": 6,
        "state_dim": 5,
        "model_file": "ssh_dqn.pth",
        # State: [cmd_len, cmd_count, threat_level, eng_depth, sudo_attempts]
        # Actions: 0=limited_shell 1=full_shell 2=fake_sudo 3=honeytoken 4=tarpit 5=block
        "reward_map": {
            # (action, context) -> reward shaping hints for bootstrap
            # High reward = action maximizes engagement duration
            "long_cmd_threat5":   {4: 2.0, 5: 1.5, 2: 1.0},  # tarpit dangerous cmds
            "sudo_attempt":       {2: 3.0, 3: 2.0},           # sudo trap is gold
            "early_cmd":          {0: 1.0, 5: 1.5},           # frustrate early
            "deep_exploration":   {1: 2.5, 3: 3.0},           # reward deep sessions
        }
    },
    "HTTP": {
        "n_actions": 5,
        "state_dim": 5,
        "model_file": "http_dqn.pth",
        # State: [payload_len, is_malicious, attack_count, eng_depth, is_scanner]
        # Actions: 0=dashboard 1=admin_panel 2=waf_block 3=tarpit 4=captcha
        "reward_map": {}
    },
    "FTP": {
        "n_actions": 5,
        "state_dim": 5,
        "model_file": "ftp_dqn.pth",
        # State: [cmd_len, login_attempts, cmd_count, downloaded_files, eng_depth]
        # Actions: 0=fake_fs 1=honeytoken_retr 2=tarpit_data 3=fake_stor 4=reject
        "reward_map": {}
    },
    "TELNET": {
        "n_actions": 5,
        "state_dim": 5,
        "model_file": "telnet_dqn.pth",
        # State: [cmd_len, cmd_count, threat_level, login_attempts, eng_depth]
        # Actions: 0=busybox 1=perm_denied 2=tarpit 3=wget_bait 4=config_reveal
        "reward_map": {}
    },
}

# ── The DQN Network ────────────────────────────────────────────────────────────
class DQN(nn.Module):
    """
    Same architecture as brain.py — MUST stay in sync.
    Input:  5 features (state vector from trap)
    Output: Q-value for each action
    """
    def __init__(self, state_dim, n_actions):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(state_dim, 64), nn.ReLU(),
            nn.Linear(64, 64),        nn.ReLU(),
            nn.Linear(64, n_actions)
        )

    def forward(self, x):
        return self.net(x)

# ── Replay Buffer ──────────────────────────────────────────────────────────────
class ReplayBuffer:
    """
    Stores experience tuples: (state, action, reward, next_state, done)
    Random sampling breaks temporal correlations — critical for stable training.
    Without this, the network would overfit to the most recent experience.
    """
    def __init__(self, capacity):
        self.buf = deque(maxlen=capacity)

    def push(self, state, action, reward, next_state, done):
        self.buf.append((
            np.array(state,      dtype=np.float32),
            int(action),
            float(reward),
            np.array(next_state, dtype=np.float32),
            float(done)
        ))

    def sample(self, batch_size):
        batch = random.sample(self.buf, batch_size)
        states, actions, rewards, next_states, dones = zip(*batch)
        return (
            torch.tensor(np.array(states),      dtype=torch.float32),
            torch.tensor(actions,               dtype=torch.long),
            torch.tensor(rewards,               dtype=torch.float32),
            torch.tensor(np.array(next_states), dtype=torch.float32),
            torch.tensor(dones,                 dtype=torch.float32),
        )

    def __len__(self):
        return len(self.buf)

# ── DQN Agent ─────────────────────────────────────────────────────────────────
class DQNAgent:
    """
    One agent per service. Each manages:
    - policy_net:  the network being trained
    - target_net:  frozen copy, updated every TARGET_UPDATE steps
    - replay buffer
    - epsilon for exploration
    """
    def __init__(self, service, cfg):
        self.service    = service
        self.cfg        = cfg
        self.n_actions  = cfg["n_actions"]
        self.state_dim  = cfg["state_dim"]
        self.model_file = cfg["model_file"]

        self.policy_net = DQN(self.state_dim, self.n_actions)
        self.target_net = DQN(self.state_dim, self.n_actions)

        # Load existing weights if available (warm start)
        if os.path.exists(self.model_file):
            try:
                self.policy_net.load_state_dict(
                    torch.load(self.model_file, map_location="cpu"))
                print(f"  [{service}] Warm-started from {self.model_file}")
            except Exception as e:
                print(f"  [{service}] Could not load {self.model_file}: {e} — starting fresh")

        # Target net starts as exact copy of policy net
        self.target_net.load_state_dict(self.policy_net.state_dict())
        self.target_net.eval()

        self.optimizer  = optim.Adam(self.policy_net.parameters(), lr=LR)
        self.buffer     = ReplayBuffer(BUFFER_SIZE)
        self.epsilon    = EPSILON_START
        self.steps      = 0
        self.losses     = []

    def select_action(self, state):
        """Epsilon-greedy: explore randomly or exploit learned Q-values."""
        if random.random() < self.epsilon:
            return random.randint(0, self.n_actions - 1)
        with torch.no_grad():
            s = torch.tensor(state, dtype=torch.float32).unsqueeze(0)
            return int(self.policy_net(s).argmax().item())

    def push(self, state, action, reward, next_state, done):
        self.buffer.push(state, action, reward, next_state, done)

    def train_step(self):
        """
        One Bellman update:
          target = r + γ * max_a' Q_target(s', a')   (if not terminal)
          loss   = MSE(Q_policy(s,a),  target)
        """
        if len(self.buffer) < BATCH_SIZE:
            return None

        states, actions, rewards, next_states, dones = self.buffer.sample(BATCH_SIZE)

        # Current Q values for actions that were taken
        q_current = self.policy_net(states).gather(1, actions.unsqueeze(1)).squeeze(1)

        # Target Q values — use frozen target_net for stability
        with torch.no_grad():
            q_next    = self.target_net(next_states).max(1)[0]
            q_target  = rewards + GAMMA * q_next * (1 - dones)

        loss = nn.functional.mse_loss(q_current, q_target)
        self.optimizer.zero_grad()
        loss.backward()
        # Gradient clipping — prevents exploding gradients
        nn.utils.clip_grad_norm_(self.policy_net.parameters(), 1.0)
        self.optimizer.step()

        self.steps += 1
        self.losses.append(loss.item())

        # Periodically sync target network with policy network
        if self.steps % TARGET_UPDATE == 0:
            self.target_net.load_state_dict(self.policy_net.state_dict())

        # Decay epsilon
        self.epsilon = max(EPSILON_END, self.epsilon * EPSILON_DECAY)

        return loss.item()

    def save(self):
        torch.save(self.policy_net.state_dict(), self.model_file)

    def avg_loss(self, last_n=100):
        if not self.losses: return 0.0
        return np.mean(self.losses[-last_n:])

# ── Reward Function ────────────────────────────────────────────────────────────
def compute_reward(service, action_id, state, session_duration, cmd_count,
                   is_terminal=False):
    """
    The core of DQN: what the agent is trying to maximize.

    Primary reward: connection duration (seconds).
    The longer an attacker stays, the more we learn about them.

    Shaped rewards: bonuses/penalties for specific action-state combinations
    that we know from domain knowledge should be good or bad.

    This is the key difference from behavioral cloning:
    The agent learns WHICH actions produce long sessions by trying them
    and observing what actually happened — not from our hardcoded Q-values.
    """
    # Base reward: normalized duration per step
    base = session_duration / max(cmd_count, 1)

    if is_terminal:
        # Terminal reward: total session duration (what we really care about)
        # Scaled so 60s = 1.0, 300s = 5.0, 600s = 10.0
        return session_duration / 60.0

    # Per-step shaped rewards based on action + state context
    shaped = 0.0

    if service == "SSH":
        cmd_len, cmd_count_s, threat, eng_depth, sudo_n = state
        if action_id == 2 and sudo_n >= 1:
            shaped += 2.0   # sudo trap is highly valuable
        if action_id == 3 and eng_depth >= 8:
            shaped += 3.0   # honeytoken exposure after deep engagement
        if action_id == 4 and threat == 5:
            shaped += 1.5   # tarpit on dangerous commands
        if action_id == 0 and cmd_count_s <= 3:
            shaped += 0.5   # limited shell early — cautious engagement
        if action_id == 1 and eng_depth >= 5:
            shaped += 1.5   # full shell mid-session
        # Penalties
        if action_id == 5 and eng_depth >= 10:
            shaped -= 1.0   # blocking late in session = lost engagement

    elif service == "HTTP":
        payload_len, is_mal, attack_cnt, eng_depth, is_scanner = state
        if action_id == 0 and attack_cnt >= 5:
            shaped += 2.5   # dashboard after multiple tries
        if action_id == 1 and attack_cnt >= 3:
            shaped += 2.0   # admin panel for persistent attackers
        if action_id == 2 and is_mal == 1:
            shaped += 1.5   # WAF block on injection
        if action_id == 3 and is_scanner == 1:
            shaped += 2.0   # tarpit scanners
        if action_id == 4 and attack_cnt > 5 and is_scanner == 1:
            shaped += 1.5   # CAPTCHA for heavy scanners
        if action_id == 0 and attack_cnt <= 2:
            shaped -= 0.5   # giving dashboard too early wastes opportunity

    elif service == "FTP":
        cmd_len, login_att, cmd_n, dl_n, eng_depth = state
        if action_id == 1 and cmd_n >= 3:
            shaped += 2.5   # honeytoken after some exploration
        if action_id == 3 and dl_n >= 1:
            shaped += 2.0   # fake STOR after download = they're uploading malware
        if action_id == 0 and login_att >= 3:
            shaped += 1.5   # reward invested attacker with filesystem
        if action_id == 2 and cmd_len > 20:
            shaped += 1.0   # tarpit long/complex commands

    elif service == "TELNET":
        cmd_len, cmd_n, threat, login_att, eng_depth = state
        if action_id == 3 and threat == 5:
            shaped += 3.0   # wget bait on malicious command = botnet trap
        if action_id == 4 and cmd_n >= 4:
            shaped += 2.0   # config reveal after exploration
        if action_id == 2 and threat == 5:
            shaped += 1.5   # tarpit on dangerous commands
        if action_id == 1 and eng_depth <= 5:
            shaped += 1.0   # permission tease early

    return base + shaped

# ── Synthetic Experience Generator (Bootstrap) ───────────────────────────────
def generate_bootstrap_experience(agent, service, kdd_df=None, n_episodes=1000):
    """
    Before we have real attacker data, we generate pre-train experiences.
    If kdd_df is provided, we sample genuine attack patterns from NSL-KDD.
    Otherwise, we fall back to synthetic episodes based on domain knowledge.
    """
    print(f"  [{service}] Generating {n_episodes} bootstrap episodes...")
    total_steps = 0

    # Filter KDD data for this service if available
    service_df = None
    if kdd_df is not None:
        svc_map = {"SSH": "ssh", "HTTP": "http", "FTP": "ftp", "TELNET": "telnet"}
        target_svc = svc_map.get(service, "")
        service_df = kdd_df[kdd_df['service'] == target_svc]
        if service_df.empty:
            print(f"  [{service}] No KDD records found. Falling back to synthetic.")
            service_df = None

    for ep in range(n_episodes):
        # Simulate a plausible attack session length and duration
        session_len   = random.randint(3, 25)
        session_dur   = random.uniform(10, 300)
        login_att     = random.randint(1, 4)

        prev_state = None
        prev_action = None

        kdd_sample = None
        if service_df is not None:
            kdd_sample = service_df.sample(n=session_len, replace=True).to_dict('records')

        for step in range(session_len):
            if kdd_sample is not None:
                row = kdd_sample[step]
                if service == "SSH":
                    cmd_len   = float(row['src_bytes']) % 1000
                    cmd_n     = step + 1
                    threat    = 5 if row['label'] != 'normal' else 1
                    eng_depth = float(row['srv_count']) % 50 + step
                    sudo_n    = float(row['su_attempted'])
                    state = [cmd_len, cmd_n, threat, eng_depth, sudo_n]

                elif service == "HTTP":
                    payload   = float(row['src_bytes']) % 2000
                    is_mal    = 1 if row['label'] != 'normal' else 0
                    att_cnt   = step + 1
                    eng_depth = float(row['srv_count']) % 50 + step
                    is_scan   = 1 if row['label'] in ['portsweep', 'ipsweep', 'nmap', 'satan'] else 0
                    state = [payload, is_mal, att_cnt, eng_depth, is_scan]

                elif service == "FTP":
                    cmd_len   = float(row['src_bytes']) % 500
                    cmd_n     = step + 1
                    login_att_kdd = float(row['num_failed_logins']) + (1 if row['logged_in'] else 0)
                    dl_n      = float(row['num_access_files'])
                    eng_depth = float(row['srv_count']) % 50 + step
                    state = [cmd_len, login_att_kdd, cmd_n, dl_n, eng_depth]

                elif service == "TELNET":
                    cmd_len   = float(row['src_bytes']) % 500
                    cmd_n     = step + 1
                    threat    = 5 if row['label'] != 'normal' else 1
                    login_att_kdd = float(row['num_failed_logins'])
                    eng_depth = float(row['srv_count']) % 50 + step
                    state = [cmd_len, cmd_n, threat, login_att_kdd, eng_depth]
            else:
                # Generate a realistic state synthetically
                if service == "SSH":
                    cmd_len   = random.randint(2, 50)
                    cmd_n     = step + 1
                    threat    = random.choice([1, 1, 1, 5, 5])  # mostly low threat
                    eng_depth = cmd_n
                    sudo_n    = random.randint(0, min(step, 4))
                    state = [cmd_len, cmd_n, threat, eng_depth, sudo_n]

                elif service == "HTTP":
                    payload   = random.randint(5, 100)
                    is_mal    = random.choice([0, 0, 1])
                    att_cnt   = step + 1
                    eng_depth = att_cnt
                    is_scan   = random.choice([0, 0, 0, 1])
                    state = [payload, is_mal, att_cnt, eng_depth, is_scan]

                elif service == "FTP":
                    cmd_len  = random.randint(3, 30)
                    cmd_n    = step + 1
                    dl_n     = random.randint(0, min(step, 5))
                    eng_depth = cmd_n
                    state = [cmd_len, login_att, cmd_n, dl_n, eng_depth]

                elif service == "TELNET":
                    cmd_len   = random.randint(2, 40)
                    cmd_n     = step + 1
                    threat    = random.choice([1, 1, 5])
                    eng_depth = cmd_n
                    state = [cmd_len, cmd_n, threat, login_att, eng_depth]

            is_terminal = (step == session_len - 1)
            action = agent.select_action(state)

            reward = compute_reward(
                service, action, state,
                session_dur, session_len,
                is_terminal=is_terminal
            )

            next_state = [x + random.uniform(-0.5, 0.5) for x in state]

            if prev_state is not None:
                agent.push(prev_state, prev_action,
                           compute_reward(service, prev_action, prev_state,
                                          session_dur, session_len),
                           state, False)

            if is_terminal:
                agent.push(state, action, reward, next_state, True)

            prev_state  = state
            prev_action = action

            agent.train_step()
            total_steps += 1

    print(f"  [{service}] Bootstrap done — {total_steps} steps, "
          f"avg_loss={agent.avg_loss():.4f}, epsilon={agent.epsilon:.3f}")

# ── MongoDB Experience Reader ─────────────────────────────────────────────────
def sessions_from_mongo(db, service, since_id=None, limit=500):
    """
    Read real attacker sessions from MongoDB and convert them to
    (state, action, reward, next_state, done) tuples for training.

    The brain already logs every action taken + state vector.
    We reconstruct experience tuples from these logs.
    """
    col = db["honeypot_db"]["attacks"]
    query = {"service": service.upper()}
    if since_id:
        query["_id"] = {"$gt": since_id}

    # Get recent sessions grouped by IP
    pipeline = [
        {"$match": query},
        {"$sort": {"timestamp": 1}},
        {"$limit": limit * 10},
    ]

    docs = list(col.aggregate(pipeline))
    if not docs:
        return [], None

    # Group by attacker IP to reconstruct sessions
    sessions = {}
    for doc in docs:
        ip  = doc.get("attacker_ip", "unknown")
        act = doc.get("action_taken", "")
        if act in ("AUTH_FAILED", "PENDING"):
            continue
        if ip not in sessions:
            sessions[ip] = []
        sessions[ip].append(doc)

    experiences = []
    last_id = docs[-1]["_id"] if docs else None

    for ip, session_docs in sessions.items():
        if len(session_docs) < 2:
            continue

        # Find the SESSION_END document for this IP
        end_docs = [d for d in session_docs if d.get("action_taken") == "SESSION_END"]
        action_docs = [d for d in session_docs if d.get("action_taken") not in
                       ("SESSION_END", "AUTH_FAILED", "PENDING")]

        if not action_docs:
            continue

        session_dur = end_docs[0].get("duration", 30) if end_docs else 30
        session_len = len(action_docs)

        for i, doc in enumerate(action_docs):
            sv = doc.get("state_vector", [0,0,0,0,0])
            sv = (sv + [0,0,0,0,0])[:5]

            # Map action_text back to action_id
            action_text = doc.get("action_taken", "")
            action_maps = {
                "SSH":    {"LIMITED_SHELL":0,"FULL_SHELL":1,"FAKE_SUDO":2,
                           "HONEYTOKEN_EXPOSE":3,"TARPIT":4,"CONTROLLED_FAIL":5},
                "HTTP":   {"LIVE_DASHBOARD":0,"FAKE_ADMIN_PANEL":1,"WAF_BLOCK_403":2,
                           "TARPIT":3,"CAPTCHA_RATELIMIT":4},
                "FTP":    {"FAKE_FILESYSTEM":0,"HONEYTOKEN_RETR":1,"TARPIT_DATA_CONN":2,
                           "FAKE_STOR_ACCEPT":3,"LOGIN_REJECTED":4},
                "TELNET": {"BUSYBOX_SHELL":0,"INVALID_LOOP":1,"TARPIT":2,
                           "WGET_BAIT":3,"CONFIG_REVEAL":4},
            }
            action_id = action_maps.get(service, {}).get(action_text, 0)
            is_terminal = (i == session_len - 1)

            # Next state
            if i + 1 < len(action_docs):
                next_sv = action_docs[i+1].get("state_vector", sv)
                next_sv = (next_sv + [0,0,0,0,0])[:5]
            else:
                next_sv = sv

            reward = compute_reward(
                service, action_id, sv,
                session_dur, session_len,
                is_terminal=is_terminal
            )

            experiences.append((sv, action_id, reward, next_sv, float(is_terminal)))

    return experiences, last_id

# ── Training Modes ────────────────────────────────────────────────────────────
def run_bootstrap(agents, kdd_path=""):
    """Phase 1: Pre-train all agents on synthetic or NSL-KDD experience."""
    print("\n=== PHASE 1: Bootstrap Training ===")
    
    kdd_df = None
    if kdd_path and os.path.exists(kdd_path):
        print(f"Loading NSL-KDD dataset from {kdd_path}...")
        try:
            import pandas as pd
            cols = ["duration", "protocol_type", "service", "flag", "src_bytes",
                "dst_bytes", "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
                "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
                "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
                "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
                "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
                "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
                "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
                "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
                "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty"]
            kdd_df = pd.read_csv(kdd_path, names=cols)
            print(f"Loaded {len(kdd_df)} records from NSL-KDD dataset.")
        except ImportError:
            print("[WARN] pandas not installed! Falling back to synthetic data.")
        except Exception as e:
            print(f"[WARN] Could not load NSL-KDD data: {e}")

    if kdd_df is not None:
        print("Using NSL-KDD data for initial policy...\n")
    else:
        print("Generating synthetic attack experiences for initial policy...\n")

    for service, agent in agents.items():
        generate_bootstrap_experience(agent, service, kdd_df=kdd_df, n_episodes=BOOTSTRAP_EPISODES)
        agent.save()
        print(f"  [{service}] Saved to {agent.model_file}")
    print("\nBootstrap complete. Models saved.")

def run_live(agents, db, epochs=5):
    """Phase 2: Train on real MongoDB sessions."""
    print("\n=== PHASE 2: Live Training from MongoDB ===")
    last_ids = {svc: None for svc in agents}

    for epoch in range(epochs):
        print(f"\n--- Epoch {epoch+1}/{epochs} ---")
        total_exp = 0

        for service, agent in agents.items():
            experiences, last_id = sessions_from_mongo(
                db, service, last_ids[service])
            last_ids[service] = last_id or last_ids[service]

            for (state, action, reward, next_state, done) in experiences:
                agent.push(state, action, reward, next_state, done)
                agent.train_step()

            total_exp += len(experiences)
            print(f"  [{service}] {len(experiences):4d} exp | "
                  f"loss={agent.avg_loss():.4f} | "
                  f"buffer={len(agent.buffer):5d} | "
                  f"eps={agent.epsilon:.3f}")

        if total_exp == 0:
            print("  No new sessions found — waiting 30s...")
            time.sleep(30)

        # Save after each epoch
        for agent in agents.values():
            agent.save()

    print("\nLive training complete. Models saved.")

def run_continuous(agents, db):
    """Phase 3: Keep training forever as new sessions arrive."""
    print("\n=== PHASE 3: Continuous Training ===")
    print("Training continuously. Press Ctrl+C to stop.\n")
    last_ids   = {svc: None for svc in agents}
    iteration  = 0
    session_threshold = 10  # retrain every 10 new sessions

    while True:
        iteration += 1
        new_sessions = 0
        log_parts = []

        for service, agent in agents.items():
            experiences, last_id = sessions_from_mongo(
                db, service, last_ids[service], limit=200)
            if last_id:
                last_ids[service] = last_id

            for (state, action, reward, next_state, done) in experiences:
                agent.push(state, action, reward, next_state, done)

            # Train multiple steps per new batch
            steps_done = 0
            for _ in range(min(len(experiences) * 3, 500)):
                loss = agent.train_step()
                if loss: steps_done += 1

            new_sessions += len(experiences)
            log_parts.append(
                f"{service}[exp={len(experiences)},loss={agent.avg_loss():.3f},"
                f"eps={agent.epsilon:.2f}]"
            )

        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] iter={iteration:4d} | " + " | ".join(log_parts))

        if iteration % 10 == 0:
            for service, agent in agents.items():
                agent.save()
            print(f"  Saved all models at iteration {iteration}")

        # Wait proportional to how much new data arrived
        sleep_time = 10 if new_sessions > 0 else 30
        time.sleep(sleep_time)

# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Real DQN Training for IoT Honeypot Brain")
    parser.add_argument("--mode", choices=["bootstrap","live","continuous","all"],
                        default="all",
                        help="bootstrap=synthetic only | live=MongoDB batch | "
                             "continuous=run forever | all=bootstrap then continuous")
    parser.add_argument("--mongo", default=MONGO_URI,
                        help="MongoDB URI (default: mongodb://localhost:27017/)")
    parser.add_argument("--epochs", type=int, default=5,
                        help="Epochs for live mode")
    parser.add_argument("--kdd-path", type=str, default="KDDTrain+.txt",
                        help="Path to KDDTrain+.txt for NSL-KDD bootstrap training")
    args = parser.parse_args()

    print("=" * 60)
    print("  IoT Honeypot — Real DQN Training")
    print("=" * 60)
    print(f"  Mode:         {args.mode}")
    print(f"  MongoDB:      {args.mongo}")
    print(f"  Gamma:        {GAMMA}")
    print(f"  LR:           {LR}")
    print(f"  Batch size:   {BATCH_SIZE}")
    print(f"  Buffer size:  {BUFFER_SIZE}")
    print(f"  Target upd:   every {TARGET_UPDATE} steps")
    print(f"  Epsilon:      {EPSILON_START} → {EPSILON_END} (decay {EPSILON_DECAY})")
    print("=" * 60)

    # Build agents
    agents = {}
    for service, cfg in SERVICE_CFG.items():
        print(f"\n[{service}] Initializing agent ({cfg['n_actions']} actions)...")
        agents[service] = DQNAgent(service, cfg)

    # Connect MongoDB
    db = None
    if args.mode in ("live", "continuous", "all"):
        try:
            db = pymongo.MongoClient(args.mongo, serverSelectionTimeoutMS=5000)
            db.server_info()
            print(f"\n[OK] MongoDB connected at {args.mongo}")
        except Exception as e:
            print(f"\n[WARN] MongoDB unavailable: {e}")
            print("       Live/continuous mode requires MongoDB.")
            if args.mode != "all":
                return
            print("       Falling back to bootstrap-only mode.")
            args.mode = "bootstrap"

    # Run selected mode
    if args.mode == "bootstrap":
        run_bootstrap(agents, kdd_path=args.kdd_path)

    elif args.mode == "live":
        if db is None: return
        run_live(agents, db, epochs=args.epochs)

    elif args.mode == "continuous":
        if db is None: return
        run_continuous(agents, db)

    elif args.mode == "all":
        run_bootstrap(agents, kdd_path=args.kdd_path)
        if db is not None:
            run_continuous(agents, db)
        else:
            print("\nNo MongoDB — running bootstrap only.")

    print("\n=== Training Complete ===")
    print("Models saved:")
    for service, agent in agents.items():
        size = os.path.getsize(agent.model_file) if os.path.exists(agent.model_file) else 0
        print(f"  {agent.model_file:25s}  ({size//1024} KB)")
    print("\nNext steps:")
    print("  1. Copy .pth files to ~/iot-honeypot/brain/")
    print("  2. sudo docker-compose build --no-cache brain")
    print("  3. sudo docker-compose up -d brain")

if __name__ == "__main__":
    main()
