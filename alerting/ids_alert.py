#!/usr/bin/env python3

import hashlib
import ipaddress
import json
import sys
import os
import urllib.parse
import urllib.request
from datetime import datetime, timezone


ENV_FILE = "/etc/ids-telegram.env"
STATE_DIR = "/run/ids-response"


def load_env(path):
    config = {}

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)

            config[key.strip()] = (
                value.strip()
                .strip('"')
                .strip("'")
            )

    return config


CONFIG = load_env(ENV_FILE)

BOT_TOKEN = CONFIG["TELEGRAM_BOT_TOKEN"]
CHAT_ID = CONFIG["TELEGRAM_CHAT_ID"]


def log(message):
    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    with open(
        "/var/log/ids_active_response.log",
        "a",
        encoding="utf-8"
    ) as f:
        f.write(
            f"[{timestamp}] {message}\n"
        )


def validate_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)

        return (
            addr.version == 4
            and not addr.is_loopback
            and not addr.is_multicast
            and not addr.is_unspecified
            and not addr.is_reserved
        )

    except ValueError:
        return False


def make_case_id(alert):
    alert_id = alert.get("id", "")

    data = alert.get("data", {})

    src_ip = (
        data.get("src_ip")
        or data.get("srcip")
        or ""
    )

    raw = f"{alert_id}:{src_ip}".encode(
        "utf-8"
    )

    return hashlib.sha256(raw).hexdigest()[:12]


def save_case(case_id, case):
    os.makedirs(
        STATE_DIR,
        exist_ok=True
    )

    path = os.path.join(
        STATE_DIR,
        f"case_{case_id}.json"
    )

    temp = path + ".tmp"

    with open(
        temp,
        "w",
        encoding="utf-8"
    ) as f:
        json.dump(case, f)

    os.replace(temp, path)


def telegram_send(text, keyboard):
    url = (
        f"https://api.telegram.org/"
        f"bot{BOT_TOKEN}/sendMessage"
    )

    payload = urllib.parse.urlencode({
        "chat_id": CHAT_ID,
        "text": text,
        "reply_markup": json.dumps(
            keyboard
        )
    }).encode("utf-8")

    request = urllib.request.Request(
        url,
        data=payload,
        method="POST"
    )

    with urllib.request.urlopen(
        request,
        timeout=15
    ) as response:

        return json.loads(
            response.read().decode(
                "utf-8"
            )
        )


def process_alert(alert):

    rule = alert.get(
        "rule",
        {}
    )

    data = alert.get(
        "data",
        {}
    )

    agent = alert.get(
        "agent",
        {}
    )

    # Hanya rule IDS DoS.
    if str(rule.get("id")) != "100100":
        return

    src_ip = (
        data.get("src_ip")
        or data.get("srcip")
    )

    if not src_ip:

        log(
            "ABORT: source IP tidak ditemukan"
        )

        return

    if not validate_ip(src_ip):

        log(
            f"ABORT: invalid source IP={src_ip}"
        )

        return

    rtt_ms = data.get(
        "rtt_ms",
        "unknown"
    )

    cpu_load = data.get(
        "cpu_load",
        "unknown"
    )

    device_id = (
        data.get("device")
        or data.get("device_id")
        or "unknown"
    )

    case_id = make_case_id(
        alert
    )

    case = {
        "case_id": case_id,
        "created_at": datetime.now(
            timezone.utc
        ).isoformat(),

        "src_ip": src_ip,
        "rtt_ms": rtt_ms,
        "cpu_load": cpu_load,
        "device_id": device_id,

        "rule_id": str(
            rule.get("id", "")
        ),

        "rule_level": rule.get(
            "level"
        ),

        "alert_id": alert.get(
            "id",
            ""
        ),

        "agent_id": agent.get(
            "id",
            ""
        ),

        "agent_name": agent.get(
            "name",
            ""
        ),

        "status": "PENDING",
        "message_id": None
    }

    save_case(
        case_id,
        case
    )

    keyboard = {
        "inline_keyboard": [[
            {
                "text": "🟡 IGNORE — SKIP AUTO-BLOCK",
                "callback_data":
                    f"ids:ignore:{case_id}"
            }
        ]]
    }

    text = (
        "🚨 WAZUH IDS ALERT\n\n"
        "⚠️ CONFIRMED DoS ATTACK\n\n"

        f"Device    : {device_id}\n"
        f"Source IP : {src_ip}\n"
        f"RTT       : {rtt_ms} ms\n"
        f"CPU Load  : {cpu_load}%\n"

        f"Rule ID   : {rule.get('id')}\n"
        f"Level     : {rule.get('level')}\n"
        f"Agent     : {agent.get('name')}\n\n"

        "⏳ Decision window: 60 detik\n"
        "Tanpa respons → IPS tetap melakukan Auto Block saat threshold tercapai.\n\n"

        "Tekan IGNORE untuk menahan Auto Block pada siklus serangan ini:"
    )

    try:

        result = telegram_send(
            text,
            keyboard
        )

        if result.get("ok"):

            message_id = (
                result["result"]
                ["message_id"]
            )

            case["message_id"] = (
                message_id
            )

            save_case(
                case_id,
                case
            )

            log(
                f"ALERT_SENT "
                f"case={case_id} "
                f"ip={src_ip} "
                f"message={message_id}"
            )

        else:

            log(
                f"TELEGRAM_FAILED "
                f"case={case_id}"
            )

    except Exception as exc:

        log(
            f"TELEGRAM_ERROR "
            f"case={case_id} "
            f"error={exc}"
        )


def main():
    log("AR_PROCESS_STARTED")

    os.makedirs(
        STATE_DIR,
        exist_ok=True
    )

    for line in [sys.stdin.readline()]:

        line = line.strip()

        if not line:
            continue

        try:

            message = json.loads(
                line
            )

        except json.JSONDecodeError:

            log(
                "INVALID_JSON"
            )

            continue
            log(
                "AR_RAW "
                + line[:1000]
            )
        if message.get(
            "command"
        ) != "add":

            continue

        alert = (
            message
            .get("parameters", {})
            .get("alert", {})
        )

        if alert:
            process_alert(alert)


if __name__ == "__main__":
    main()
