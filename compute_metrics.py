"""
Research Metrics Calculator for IoT Honeypot
=============================================
Computes three research-grade deception metrics from MongoDB session data:

  1. Behavioral Engagement Index (BEI)
     BEI = 0.4*D + 0.3*C + 0.2*P + 0.1*H
     Where D=normalized dwell time, C=normalized command count,
     P=sudo/privilege attempts, H=honeytoken interactions

  2. Deception Retention Rate (DRR)
     DRR = (Sessions continuing after adaptive deception / Total deception-exposed sessions) * 100

  3. Escalation Persistence Score (EPS)
     EPS = Commands after first sudo attempt / Total commands in session

Usage (run inside VM where MongoDB lives):
  python3 compute_metrics.py
  python3 compute_metrics.py --mongo mongodb://localhost:27017/
  python3 compute_metrics.py --service SSH
  python3 compute_metrics.py --csv results.csv
  python3 compute_metrics.py --json results.json
"""

import argparse
import json
import os
import sys
from datetime import datetime
from collections import defaultdict

try:
    import pymongo
except ImportError:
    print("[ERROR] pymongo not installed. Run: pip install pymongo")
    sys.exit(1)

# ── MongoDB Configuration ────────────────────────────────────────────────────
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")

# ── Deception actions — these are the adaptive responses that test attacker belief
DECEPTION_ACTIONS = {
    "SSH":    {"FAKE_SUDO", "TARPIT", "HONEYTOKEN_EXPOSE", "CONTROLLED_FAIL"},
    "HTTP":   {"TARPIT", "WAF_BLOCK_403", "CAPTCHA_RATELIMIT", "FAKE_ADMIN_PANEL"},
    "FTP":    {"TARPIT_DATA_CONN", "HONEYTOKEN_RETR", "FAKE_STOR_ACCEPT"},
    "TELNET": {"TARPIT", "WGET_BAIT", "CONFIG_REVEAL", "INVALID_LOOP"},
}

# Privilege-related actions (for EPS)
PRIVILEGE_ACTIONS = {
    "SSH":    {"FAKE_SUDO"},
    "HTTP":   {"FAKE_ADMIN_PANEL"},       # admin panel = privilege escalation attempt
    "FTP":    {"FAKE_STOR_ACCEPT"},       # upload attempt = privilege action
    "TELNET": {"CONFIG_REVEAL"},          # config access = privilege probe
}

# Honeytoken actions (for BEI)
HONEYTOKEN_ACTIONS = {
    "SSH":    {"HONEYTOKEN_EXPOSE"},
    "HTTP":   {"FAKE_ADMIN_PANEL"},       # dashboard with fake creds = honeytoken
    "FTP":    {"HONEYTOKEN_RETR"},
    "TELNET": {"CONFIG_REVEAL", "WGET_BAIT"},
}


def fetch_sessions(db, service_filter=None):
    """
    Reconstruct attacker sessions from MongoDB attack logs.

    Returns a list of session dicts:
    {
        "ip": str,
        "service": str,
        "duration": float,        # seconds
        "commands": int,          # total commands typed
        "actions": [str],         # ordered list of brain actions taken
        "sudo_attempts": int,     # privilege escalation attempts from state_vector
        "honeytoken_hits": int,   # honeytoken interaction count
        "deception_exposed": bool,# session saw adaptive deception
        "continued_after_deception": bool,  # commands continued after deception
        "first_priv_idx": int|None,  # command index of first privilege attempt
        "commands_after_priv": int,  # commands after first privilege attempt
        "timestamp": datetime,
    }
    """
    col = db["honeypot_db"]["attacks"]

    query = {}
    if service_filter:
        query["service"] = service_filter.upper()

    # Pull all records sorted by timestamp
    pipeline = [
        {"$match": query},
        {"$sort": {"timestamp": 1}},
    ]
    docs = list(col.aggregate(pipeline))
    if not docs:
        print("[WARN] No attack records found in MongoDB.")
        return []

    print(f"[OK] Fetched {len(docs)} raw records from MongoDB.")

    # Group by (attacker_ip, service) to reconstruct sessions
    # A SESSION_END marker delineates session boundaries
    raw_sessions = defaultdict(list)
    for doc in docs:
        ip = doc.get("attacker_ip", "unknown")
        svc = doc.get("service", "UNKNOWN")
        raw_sessions[(ip, svc)].append(doc)

    sessions = []

    for (ip, svc), session_docs in raw_sessions.items():
        # Split into sub-sessions using SESSION_END markers
        current_batch = []
        for doc in session_docs:
            action = doc.get("action_taken", "")
            if action == "SESSION_END":
                # Process this completed session
                if current_batch:
                    session = _process_session(ip, svc, current_batch, doc)
                    if session:
                        sessions.append(session)
                current_batch = []
            elif action not in ("AUTH_FAILED", "PENDING"):
                current_batch.append(doc)

        # Handle sessions without SESSION_END (still active or lost)
        if current_batch:
            session = _process_session(ip, svc, current_batch, end_doc=None)
            if session:
                sessions.append(session)

    print(f"[OK] Reconstructed {len(sessions)} complete sessions.")
    return sessions


def _process_session(ip, svc, action_docs, end_doc=None):
    """Convert a sequence of action documents into a session dict."""
    if not action_docs:
        return None

    actions = [d.get("action_taken", "") for d in action_docs]
    duration = end_doc.get("duration", 0) if end_doc else 0
    commands = end_doc.get("commands_typed", len(action_docs)) if end_doc else len(action_docs)
    timestamp = action_docs[0].get("timestamp", datetime.now())

    # Count sudo/privilege attempts from state_vector
    # SSH state_vector[4] = sudo_attempts count
    sudo_attempts = 0
    for doc in action_docs:
        sv = doc.get("state_vector", [])
        if svc == "SSH" and len(sv) >= 5:
            sudo_attempts = max(sudo_attempts, int(sv[4]))

    # Also count by action type
    svc_priv = PRIVILEGE_ACTIONS.get(svc, set())
    svc_deception = DECEPTION_ACTIONS.get(svc, set())
    svc_honeytoken = HONEYTOKEN_ACTIONS.get(svc, set())

    priv_count_by_action = sum(1 for a in actions if a in svc_priv)
    sudo_attempts = max(sudo_attempts, priv_count_by_action)

    honeytoken_hits = sum(1 for a in actions if a in svc_honeytoken)

    # Deception exposure analysis
    deception_exposed = any(a in svc_deception for a in actions)

    # Did attacker continue AFTER deception?
    continued_after_deception = False
    if deception_exposed:
        # Find last deception action index
        last_deception_idx = max(
            (i for i, a in enumerate(actions) if a in svc_deception),
            default=-1
        )
        # If there are actions after the last deception, attacker continued
        if last_deception_idx >= 0 and last_deception_idx < len(actions) - 1:
            continued_after_deception = True

    # First privilege attempt index (for EPS)
    first_priv_idx = None
    for i, a in enumerate(actions):
        if a in svc_priv:
            first_priv_idx = i
            break
    # Also check sudo from state_vector for SSH
    if svc == "SSH" and first_priv_idx is None:
        for i, doc in enumerate(action_docs):
            sv = doc.get("state_vector", [])
            if len(sv) >= 5 and sv[4] > 0:
                first_priv_idx = i
                break

    commands_after_priv = 0
    if first_priv_idx is not None:
        commands_after_priv = max(0, len(actions) - first_priv_idx - 1)

    return {
        "ip": ip,
        "service": svc,
        "duration": float(duration),
        "commands": int(commands),
        "actions": actions,
        "sudo_attempts": sudo_attempts,
        "honeytoken_hits": honeytoken_hits,
        "deception_exposed": deception_exposed,
        "continued_after_deception": continued_after_deception,
        "first_priv_idx": first_priv_idx,
        "commands_after_priv": commands_after_priv,
        "timestamp": timestamp,
    }


# ── Metric 1: Behavioral Engagement Index (BEI) ─────────────────────────────
def compute_bei(sessions):
    """
    BEI = 0.4*D + 0.3*C + 0.2*P + 0.1*H

    D = normalized session duration  (0–1, capped at 600s = max engagement)
    C = normalized command count     (0–1, capped at 50 commands)
    P = normalized privilege attempts (0–1, capped at 10)
    H = normalized honeytoken hits   (0–1, capped at 5)

    Returns: list of (session, bei_score) tuples + aggregate stats
    """
    MAX_DURATION = 600.0   # 10 minutes = maximum expected engagement
    MAX_COMMANDS = 50.0    # 50 commands = deep exploration
    MAX_SUDO = 10.0        # 10 privilege attempts
    MAX_HONEYTOKEN = 5.0   # 5 honeytoken interactions

    results = []
    for s in sessions:
        D = min(s["duration"] / MAX_DURATION, 1.0)
        C = min(s["commands"] / MAX_COMMANDS, 1.0)
        P = min(s["sudo_attempts"] / MAX_SUDO, 1.0)
        H = min(s["honeytoken_hits"] / MAX_HONEYTOKEN, 1.0)

        bei = 0.4 * D + 0.3 * C + 0.2 * P + 0.1 * H

        results.append({
            "session": s,
            "D": round(D, 4),
            "C": round(C, 4),
            "P": round(P, 4),
            "H": round(H, 4),
            "BEI": round(bei, 4),
        })

    return results


# ── Metric 2: Deception Retention Rate (DRR) ────────────────────────────────
def compute_drr(sessions):
    """
    DRR = (Sessions continuing after deception / Total deception-exposed) * 100

    Returns: overall DRR + per-service breakdown
    """
    total_exposed = 0
    total_retained = 0

    per_service = defaultdict(lambda: {"exposed": 0, "retained": 0})

    for s in sessions:
        if s["deception_exposed"]:
            total_exposed += 1
            per_service[s["service"]]["exposed"] += 1

            if s["continued_after_deception"]:
                total_retained += 1
                per_service[s["service"]]["retained"] += 1

    overall_drr = (total_retained / total_exposed * 100) if total_exposed > 0 else 0.0

    service_drr = {}
    for svc, counts in per_service.items():
        if counts["exposed"] > 0:
            service_drr[svc] = {
                "exposed": counts["exposed"],
                "retained": counts["retained"],
                "DRR": round(counts["retained"] / counts["exposed"] * 100, 2),
            }

    return {
        "overall_DRR": round(overall_drr, 2),
        "total_exposed": total_exposed,
        "total_retained": total_retained,
        "per_service": service_drr,
    }


# ── Metric 3: Escalation Persistence Score (EPS) ────────────────────────────
def compute_eps(sessions):
    """
    EPS = Commands after first sudo/privilege attempt / Total commands

    Only computed for sessions that had at least one privilege attempt.
    Returns: list of (session, eps_score) tuples + aggregate stats
    """
    results = []
    for s in sessions:
        if s["first_priv_idx"] is not None and s["commands"] > 0:
            total_cmds = max(s["commands"], len(s["actions"]))
            eps = s["commands_after_priv"] / total_cmds if total_cmds > 0 else 0.0
            results.append({
                "session": s,
                "total_commands": total_cmds,
                "first_priv_at": s["first_priv_idx"],
                "commands_after": s["commands_after_priv"],
                "EPS": round(eps, 4),
            })

    return results


# ── Pretty Print ─────────────────────────────────────────────────────────────
def print_report(sessions, bei_results, drr_result, eps_results):
    """Print a formatted research report."""
    print("\n" + "=" * 72)
    print("  HONEYPOT DECEPTION METRICS REPORT")
    print("  Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("=" * 72)

    # ── Summary ──
    print(f"\n  Total Sessions Analyzed: {len(sessions)}")
    svc_counts = defaultdict(int)
    for s in sessions:
        svc_counts[s["service"]] += 1
    for svc, cnt in sorted(svc_counts.items()):
        print(f"    {svc:8s}: {cnt} sessions")

    # ── BEI ──
    print("\n" + "─" * 72)
    print("  1. BEHAVIORAL ENGAGEMENT INDEX (BEI)")
    print("     Formula: BEI = 0.4*D + 0.3*C + 0.2*P + 0.1*H")
    print("─" * 72)

    if bei_results:
        # Per-service averages
        svc_bei = defaultdict(list)
        for r in bei_results:
            svc_bei[r["session"]["service"]].append(r["BEI"])

        print(f"\n  {'Service':<10} {'Avg BEI':>10} {'Min':>8} {'Max':>8} {'Sessions':>10}")
        print(f"  {'─'*10} {'─'*10} {'─'*8} {'─'*8} {'─'*10}")
        all_bei = [r["BEI"] for r in bei_results]
        for svc in sorted(svc_bei.keys()):
            vals = svc_bei[svc]
            print(f"  {svc:<10} {sum(vals)/len(vals):>10.4f} {min(vals):>8.4f} {max(vals):>8.4f} {len(vals):>10}")
        print(f"  {'OVERALL':<10} {sum(all_bei)/len(all_bei):>10.4f} "
              f"{min(all_bei):>8.4f} {max(all_bei):>8.4f} {len(all_bei):>10}")

        # Top 5 highest BEI sessions
        top5 = sorted(bei_results, key=lambda x: x["BEI"], reverse=True)[:5]
        print(f"\n  Top 5 Highest-BEI Sessions:")
        print(f"  {'IP':<18} {'Service':<8} {'BEI':>6} {'Dur(s)':>8} {'Cmds':>6} {'Sudo':>6} {'HT':>4}")
        for r in top5:
            s = r["session"]
            print(f"  {s['ip']:<18} {s['service']:<8} {r['BEI']:>6.3f} "
                  f"{s['duration']:>8.1f} {s['commands']:>6} {s['sudo_attempts']:>6} {s['honeytoken_hits']:>4}")
    else:
        print("\n  No sessions to compute BEI.")

    # ── DRR ──
    print("\n" + "─" * 72)
    print("  2. DECEPTION RETENTION RATE (DRR)")
    print("     Formula: DRR = (Retained / Exposed) × 100")
    print("─" * 72)

    print(f"\n  Overall DRR:       {drr_result['overall_DRR']:.2f}%")
    print(f"  Total Exposed:     {drr_result['total_exposed']}")
    print(f"  Total Retained:    {drr_result['total_retained']}")

    if drr_result["per_service"]:
        print(f"\n  {'Service':<10} {'Exposed':>10} {'Retained':>10} {'DRR (%)':>10}")
        print(f"  {'─'*10} {'─'*10} {'─'*10} {'─'*10}")
        for svc, data in sorted(drr_result["per_service"].items()):
            print(f"  {svc:<10} {data['exposed']:>10} {data['retained']:>10} {data['DRR']:>10.2f}")

    # ── EPS ──
    print("\n" + "─" * 72)
    print("  3. ESCALATION PERSISTENCE SCORE (EPS)")
    print("     Formula: EPS = Commands_after_first_priv / Total_commands")
    print("─" * 72)

    if eps_results:
        svc_eps = defaultdict(list)
        for r in eps_results:
            svc_eps[r["session"]["service"]].append(r["EPS"])

        print(f"\n  {'Service':<10} {'Avg EPS':>10} {'Min':>8} {'Max':>8} {'Sessions*':>10}")
        print(f"  {'─'*10} {'─'*10} {'─'*8} {'─'*8} {'─'*10}")
        all_eps = [r["EPS"] for r in eps_results]
        for svc in sorted(svc_eps.keys()):
            vals = svc_eps[svc]
            print(f"  {svc:<10} {sum(vals)/len(vals):>10.4f} {min(vals):>8.4f} {max(vals):>8.4f} {len(vals):>10}")
        print(f"  {'OVERALL':<10} {sum(all_eps)/len(all_eps):>10.4f} "
              f"{min(all_eps):>8.4f} {max(all_eps):>8.4f} {len(all_eps):>10}")
        print(f"\n  *Only sessions with ≥1 privilege/sudo attempt are included.")

        # Top 5 highest EPS
        top5 = sorted(eps_results, key=lambda x: x["EPS"], reverse=True)[:5]
        print(f"\n  Top 5 Most Persistent Attackers (EPS):")
        print(f"  {'IP':<18} {'Service':<8} {'EPS':>6} {'TotalCmd':>10} {'1stPriv@':>10} {'CmdsAfter':>10}")
        for r in top5:
            s = r["session"]
            print(f"  {s['ip']:<18} {s['service']:<8} {r['EPS']:>6.3f} "
                  f"{r['total_commands']:>10} {r['first_priv_at']:>10} {r['commands_after']:>10}")
    else:
        print("\n  No sessions with privilege attempts found (EPS N/A).")

    # ── Research Interpretation ──
    print("\n" + "─" * 72)
    print("  RESEARCH INTERPRETATION")
    print("─" * 72)

    if bei_results:
        avg_bei = sum(r["BEI"] for r in bei_results) / len(bei_results)
        if avg_bei >= 0.5:
            print(f"  BEI={avg_bei:.3f} → HIGH: Attackers deeply believed the deception.")
        elif avg_bei >= 0.25:
            print(f"  BEI={avg_bei:.3f} → MODERATE: Reasonable attacker engagement achieved.")
        else:
            print(f"  BEI={avg_bei:.3f} → LOW: Most sessions were shallow scans.")

    drr = drr_result["overall_DRR"]
    if drr >= 60:
        print(f"  DRR={drr:.1f}% → STRONG: Deception mechanisms retained majority of attackers.")
    elif drr >= 30:
        print(f"  DRR={drr:.1f}% → MODERATE: Some attackers detected deception and left.")
    elif drr_result["total_exposed"] > 0:
        print(f"  DRR={drr:.1f}% → WEAK: Most attackers disengaged after deception exposure.")
    else:
        print(f"  DRR=N/A → No deception exposure events recorded yet.")

    if eps_results:
        avg_eps = sum(r["EPS"] for r in eps_results) / len(eps_results)
        if avg_eps >= 0.5:
            print(f"  EPS={avg_eps:.3f} → HIGH: Privilege deception highly believable.")
        elif avg_eps >= 0.25:
            print(f"  EPS={avg_eps:.3f} → MODERATE: Some attackers persisted after priv attempts.")
        else:
            print(f"  EPS={avg_eps:.3f} → LOW: Attackers abandoned quickly after priv failure.")

    print("\n" + "=" * 72)


def export_csv(bei_results, drr_result, eps_results, filepath):
    """Export per-session metrics to CSV."""
    import csv

    # Build EPS lookup
    eps_lookup = {}
    for r in eps_results:
        key = (r["session"]["ip"], r["session"]["service"])
        eps_lookup[key] = r["EPS"]

    with open(filepath, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "IP", "Service", "Duration_s", "Commands", "Sudo_Attempts",
            "Honeytoken_Hits", "BEI", "D", "C", "P", "H",
            "Deception_Exposed", "Continued_After_Deception",
            "EPS", "Timestamp"
        ])
        for r in bei_results:
            s = r["session"]
            key = (s["ip"], s["service"])
            eps_val = eps_lookup.get(key, "")
            ts = s["timestamp"].strftime("%Y-%m-%d %H:%M:%S") if hasattr(s["timestamp"], "strftime") else str(s["timestamp"])
            writer.writerow([
                s["ip"], s["service"], s["duration"], s["commands"],
                s["sudo_attempts"], s["honeytoken_hits"],
                r["BEI"], r["D"], r["C"], r["P"], r["H"],
                int(s["deception_exposed"]), int(s["continued_after_deception"]),
                eps_val, ts
            ])

    print(f"\n[OK] CSV exported to {filepath}")


def export_json(bei_results, drr_result, eps_results, filepath):
    """Export all metrics to JSON for further analysis."""
    # Build EPS lookup
    eps_lookup = {}
    for r in eps_results:
        key = (r["session"]["ip"], r["session"]["service"])
        eps_lookup[key] = {
            "EPS": r["EPS"],
            "total_commands": r["total_commands"],
            "first_priv_at": r["first_priv_at"],
            "commands_after": r["commands_after"],
        }

    output = {
        "generated": datetime.now().isoformat(),
        "total_sessions": len(bei_results),
        "metrics": {
            "BEI": {
                "description": "Behavioral Engagement Index",
                "formula": "0.4*D + 0.3*C + 0.2*P + 0.1*H",
                "average": round(sum(r["BEI"] for r in bei_results) / max(len(bei_results), 1), 4),
            },
            "DRR": drr_result,
            "EPS": {
                "description": "Escalation Persistence Score",
                "formula": "commands_after_first_priv / total_commands",
                "average": round(sum(r["EPS"] for r in eps_results) / max(len(eps_results), 1), 4),
                "sessions_with_priv": len(eps_results),
            },
        },
        "sessions": [],
    }

    for r in bei_results:
        s = r["session"]
        key = (s["ip"], s["service"])
        ts = s["timestamp"].isoformat() if hasattr(s["timestamp"], "isoformat") else str(s["timestamp"])
        entry = {
            "ip": s["ip"],
            "service": s["service"],
            "duration": s["duration"],
            "commands": s["commands"],
            "sudo_attempts": s["sudo_attempts"],
            "honeytoken_hits": s["honeytoken_hits"],
            "BEI": r["BEI"],
            "BEI_components": {"D": r["D"], "C": r["C"], "P": r["P"], "H": r["H"]},
            "deception_exposed": s["deception_exposed"],
            "continued_after_deception": s["continued_after_deception"],
            "timestamp": ts,
        }
        if key in eps_lookup:
            entry["EPS"] = eps_lookup[key]
        output["sessions"].append(entry)

    with open(filepath, "w") as f:
        json.dump(output, f, indent=2, default=str)

    print(f"\n[OK] JSON exported to {filepath}")


# ── Main ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Compute research-grade deception metrics (BEI, DRR, EPS) from honeypot MongoDB data")
    parser.add_argument("--mongo", default=MONGO_URI,
                        help="MongoDB connection URI (default: mongodb://localhost:27017/)")
    parser.add_argument("--service", default=None,
                        help="Filter by service: SSH, HTTP, FTP, TELNET (default: all)")
    parser.add_argument("--csv", default=None,
                        help="Export per-session metrics to CSV file")
    parser.add_argument("--json", default=None,
                        help="Export all metrics to JSON file")
    args = parser.parse_args()

    print("=" * 60)
    print("  Honeypot Research Metrics Calculator")
    print("=" * 60)
    print(f"  MongoDB:  {args.mongo}")
    print(f"  Service:  {args.service or 'ALL'}")
    print(f"  Time:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    # Connect to MongoDB
    try:
        client = pymongo.MongoClient(args.mongo, serverSelectionTimeoutMS=5000)
        client.server_info()
        print(f"\n[OK] Connected to MongoDB at {args.mongo}")
    except Exception as e:
        print(f"\n[ERROR] Cannot connect to MongoDB: {e}")
        print("        Make sure MongoDB is running and accessible.")
        print("        Usage: python3 compute_metrics.py --mongo mongodb://<host>:27017/")
        sys.exit(1)

    # Fetch and reconstruct sessions
    sessions = fetch_sessions(client, service_filter=args.service)
    if not sessions:
        print("\n[WARN] No sessions found. The honeypot may not have logged any attacks yet.")
        print("       Check that the 'honeypot_db.attacks' collection has data.")
        sys.exit(0)

    # Compute metrics
    bei_results = compute_bei(sessions)
    drr_result = compute_drr(sessions)
    eps_results = compute_eps(sessions)

    # Print report
    print_report(sessions, bei_results, drr_result, eps_results)

    # Export if requested
    if args.csv:
        export_csv(bei_results, drr_result, eps_results, args.csv)
    if args.json:
        export_json(bei_results, drr_result, eps_results, args.json)


if __name__ == "__main__":
    main()
