#!/usr/bin/env python3
"""WireGuard usage reporter for wg-easy.

What it does:
- Reads per-peer traffic counters from `wg-easy` container.
- Resolves peer names from wg-easy `wg0.json`.
- Sends daily usage report to Telegram.
- Sends previous-month summary on month rollover.
- Tracks monthly 1 TB limit and sends threshold alerts.

Run this script once per day at 10:00 Asia/Tomsk via cron.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.parse import urlencode
from urllib.request import Request, urlopen

try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore


WG_CONTAINER = os.getenv("WG_CONTAINER", "wg-easy")
WG_INTERFACE = os.getenv("WG_INTERFACE", "wg0")
WG_JSON_PATH = os.getenv("WG_JSON_PATH", "/etc/wireguard/wg0.json")
STATE_PATH = Path(os.getenv("WG_USAGE_STATE", "/root/wg_usage_state.json"))

# ВАЖНО: Установите ваш Telegram bot token и chat ID в переменные окружения!
# или закомментируйте ниже и передайте через .env
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")  # Заполните вашим bot token
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")      # Заполните вашим Telegram chat ID

LIMIT_BYTES = int(os.getenv("VPN_LIMIT_BYTES", str(1024**4)))  # 1 TiB by default
ALERT_THRESHOLDS = [
    int(x.strip())
    for x in os.getenv("ALERT_THRESHOLDS", "80,90,100").split(",")
    if x.strip()
]

TIMEZONE = os.getenv("WG_REPORT_TZ", "Asia/Tomsk")


@dataclass
class PeerUsage:
    public_key: str
    name: str
    address: str
    total_bytes: int


def run_cmd(cmd: List[str]) -> str:
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        stderr = p.stderr.strip()
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{stderr}")
    return p.stdout


def now_tz() -> datetime:
    if ZoneInfo is None:
        return datetime.utcnow()
    try:
        return datetime.now(ZoneInfo(TIMEZONE))
    except Exception:
        return datetime.utcnow()


def human_bytes(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    val = float(n)
    i = 0
    while val >= 1024 and i < len(units) - 1:
        val /= 1024
        i += 1
    return f"{val:.2f} {units[i]}"


def load_state() -> dict:
    if not STATE_PATH.exists():
        return {}
    try:
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_state(state: dict) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def tg_send(text: str) -> None:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        raise RuntimeError("Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID")

    payload = urlencode({"chat_id": TELEGRAM_CHAT_ID, "text": text})
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    req = Request(url, data=payload.encode("utf-8"), method="POST")
    with urlopen(req, timeout=15) as resp:
        if resp.status != 200:
            raise RuntimeError(f"Telegram API HTTP {resp.status}")


def load_name_map() -> Dict[str, Tuple[str, str]]:
    """Return map public_key -> (name, address)."""
    raw = run_cmd([
        "docker",
        "exec",
        WG_CONTAINER,
        "sh",
        "-lc",
        f"cat {WG_JSON_PATH}",
    ])
    data = json.loads(raw)

    clients = data.get("clients", {}) if isinstance(data, dict) else {}
    out: Dict[str, Tuple[str, str]] = {}
    if isinstance(clients, dict):
        for _cid, c in clients.items():
            if not isinstance(c, dict):
                continue
            pub = str(c.get("publicKey") or "").strip()
            if not pub:
                continue
            name = str(c.get("name") or "unknown")
            addr = str(c.get("address") or "")
            out[pub] = (name, addr)
    return out


def read_wg_dump() -> List[Tuple[str, int, int]]:
    """Return list of (public_key, rx, tx) from wg dump."""
    out = run_cmd([
        "docker",
        "exec",
        WG_CONTAINER,
        "sh",
        "-lc",
        f"wg show {WG_INTERFACE} dump",
    ])
    rows = []
    for i, line in enumerate(out.splitlines()):
        # first line is interface metadata
        if i == 0:
            continue
        cols = line.split("\t")
        if len(cols) < 7:
            continue
        pub = cols[0].strip()
        try:
            rx = int(cols[5])
            tx = int(cols[6])
        except ValueError:
            continue
        rows.append((pub, rx, tx))
    return rows


def build_peer_usage() -> Dict[str, PeerUsage]:
    name_map = load_name_map()
    dump_rows = read_wg_dump()
    result: Dict[str, PeerUsage] = {}
    for pub, rx, tx in dump_rows:
        name, addr = name_map.get(pub, (f"unknown:{pub[:8]}", ""))
        result[pub] = PeerUsage(public_key=pub, name=name, address=addr, total_bytes=rx + tx)
    return result


def format_usage_lines(title: str, items: List[Tuple[str, int]], max_rows: int = 20) -> str:
    lines = [title]
    if not items:
        lines.append("- no traffic")
        return "\n".join(lines)

    for i, (name, b) in enumerate(items[:max_rows], start=1):
        lines.append(f"{i}. {name}: {human_bytes(b)}")

    if len(items) > max_rows:
        lines.append(f"... and {len(items) - max_rows} more")
    return "\n".join(lines)


def aggregate_by_name(delta_by_pub: Dict[str, int], peers: Dict[str, PeerUsage]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for pub, delta in delta_by_pub.items():
        if delta <= 0:
            continue
        name = peers.get(pub).name if pub in peers else f"unknown:{pub[:8]}"
        out[name] = out.get(name, 0) + delta
    return out


def main() -> int:
    now = now_tz()
    day_key = now.strftime("%Y-%m-%d")
    month_key = now.strftime("%Y-%m")

    peers = build_peer_usage()
    current_totals = {pub: p.total_bytes for pub, p in peers.items()}

    state = load_state()
    last_totals: Dict[str, int] = state.get("last_totals", {})
    month_usage: Dict[str, int] = state.get("month_usage", {})
    state_month_key = state.get("month_key")
    alerted: List[int] = state.get("alerted_thresholds", [])

    # First run: initialize baseline to avoid huge fake delta.
    if not last_totals:
        state["last_totals"] = current_totals
        state["month_key"] = month_key
        state["month_usage"] = {}
        state["alerted_thresholds"] = []
        state["last_run"] = now.isoformat()
        save_state(state)
        tg_send(
            "WG usage initialized. Next run will send daily report.\n"
            f"Timezone: {TIMEZONE}, run_time: {now.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        return 0

    # Monthly rollover report for the previous month.
    if state_month_key and state_month_key != month_key:
        prev_month_total = sum(int(v) for v in month_usage.values())
        ranked_prev = sorted(month_usage.items(), key=lambda x: x[1], reverse=True)
        msg = [
            f"WG monthly report ({state_month_key})",
            f"Total: {human_bytes(prev_month_total)}",
            format_usage_lines("Top users:", ranked_prev),
        ]
        tg_send("\n\n".join(msg))
        month_usage = {}
        alerted = []

    # Delta since previous run.
    delta_by_pub: Dict[str, int] = {}
    for pub, cur in current_totals.items():
        prev = int(last_totals.get(pub, cur))
        delta = cur - prev
        if delta < 0:
            # Counter reset or interface restart.
            delta = cur
        delta_by_pub[pub] = delta

    daily_by_name = aggregate_by_name(delta_by_pub, peers)
    ranked_daily = sorted(daily_by_name.items(), key=lambda x: x[1], reverse=True)
    day_total = sum(v for _, v in ranked_daily)

    # Update month accumulator.
    for pub, delta in delta_by_pub.items():
        if delta <= 0:
            continue
        month_usage[pub] = int(month_usage.get(pub, 0)) + int(delta)

    month_by_name = aggregate_by_name(month_usage, peers)
    ranked_month = sorted(month_by_name.items(), key=lambda x: x[1], reverse=True)
    month_total = sum(v for _, v in ranked_month)

    limit_pct = (month_total / LIMIT_BYTES * 100.0) if LIMIT_BYTES > 0 else 0.0
    remain = max(0, LIMIT_BYTES - month_total)

    daily_msg = [
        f"WG daily report ({day_key} {TIMEZONE})",
        f"24h total: {human_bytes(day_total)}",
        format_usage_lines("Top users (24h):", ranked_daily),
        "",
        f"Monthly usage ({month_key}): {human_bytes(month_total)} / {human_bytes(LIMIT_BYTES)} ({limit_pct:.2f}%)",
        f"Remaining: {human_bytes(remain)}",
        format_usage_lines("Top users (month):", ranked_month),
    ]
    tg_send("\n".join(daily_msg))

    for t in sorted(set(ALERT_THRESHOLDS)):
        if t in alerted:
            continue
        if limit_pct >= t:
            tg_send(
                "WG LIMIT ALERT\n"
                f"Threshold: {t}%\n"
                f"Used: {human_bytes(month_total)} / {human_bytes(LIMIT_BYTES)} ({limit_pct:.2f}%)"
            )
            alerted.append(t)

    state["last_totals"] = current_totals
    state["month_key"] = month_key
    state["month_usage"] = month_usage
    state["alerted_thresholds"] = sorted(set(alerted))
    state["last_run"] = now.isoformat()
    save_state(state)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[ERR] {exc}", file=sys.stderr)
        raise SystemExit(1)
