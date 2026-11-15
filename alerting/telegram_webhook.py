#!/usr/bin/env python3

import json
import os
import subprocess
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone


ENV_FILE = "/etc/ids-telegram.env"
STATE_DIR = "/run/ids-response"

DECISION_TIMEOUT = 60
BLOCK_DURATION = 300


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
CHAT_ID = int(CONFIG["TELEGRAM_CHAT_ID"])


API_URL = (
    f"https://api.telegram.org/"
    f"bot{BOT_TOKEN}"
)


def log(message):
    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    with open(
        "/var/log/ids_telegram_controller.log",
        "a",
        encoding="utf-8"
    ) as f:
        f.write(f"[{timestamp}] {message}\n")


def telegram_api(method, params):
    encoded = urllib.parse.urlencode(params).encode()

    request = urllib.request.Request(
        f"{API_URL}/{method}",
        data=encoded,
        method="POST"
    )

    with urllib.request.urlopen(
        request,
        timeout=20
    ) as response:
        return json.loads(
            response.read().decode()
        )


def list_cases():
    if not os.path.isdir(STATE_DIR):
        return []

    cases = []

    for filename in os.listdir(STATE_DIR):

        if not (
            filename.startswith("case_")
            and filename.endswith(".json")
        ):
            continue

        path = os.path.join(
            STATE_DIR,
            filename
        )

        try:
            with open(
                path,
                "r",
                encoding="utf-8"
            ) as f:
                case = json.load(f)

            cases.append(case)

        except Exception:
            continue

    return cases


def case_path(case_id):
    return os.path.join(
        STATE_DIR,
        f"case_{case_id}.json"
    )


def save_case(case):
    path = case_path(case["case_id"])

    tmp = path + ".tmp"

    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(case, f)

    os.replace(tmp, path)


def get_action(case_id):
    path = os.path.join(
        STATE_DIR,
        f"action_{case_id}"
    )

    if not os.path.exists(path):
        return None

    try:
        with open(path, "r") as f:
            return f.read().strip()

    except Exception:
        return None


def clear_action(case_id):
    path = os.path.join(
        STATE_DIR,
        f"action_{case_id}"
    )

    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass


def edit_message(message_id, text):

    try:

        telegram_api(
            "editMessageText",
            {
                "chat_id": CHAT_ID,
                "message_id": message_id,
                "text": text
            }
        )

    except Exception as exc:
        log(f"EDIT_MESSAGE_ERROR {exc}")


def acknowledge_callback(callback_id, text):

    try:

        telegram_api(
            "answerCallbackQuery",
            {
                "callback_query_id": callback_id,
                "text": text,
                "show_alert": True
            }
        )

    except Exception as exc:
        log(f"CALLBACK_ERROR {exc}")


def request_ids_ignore(src_ip, case_id):
    token_path = CONFIG.get("IDS_TEST_TOKEN_PATH", "/etc/garda-iot/ids_test_token")

    with open(token_path, "r", encoding="utf-8") as f:
        token = f.read().strip()

    if not token:
        raise RuntimeError("IDS test token is empty")

    payload = json.dumps({
        "src_ip": src_ip,
        "case_id": case_id
    }).encode("utf-8")

    request = urllib.request.Request(
        "http://127.0.0.1:5000/ignore",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "X-IDS-Test-Token": token
        },
        method="POST"
    )

    with urllib.request.urlopen(request, timeout=8) as response:
        result = json.loads(response.read().decode("utf-8"))

    if not result.get("ok"):
        raise RuntimeError(result.get("error", "IGNORE rejected"))

    return result


def process_callback(update):

    callback = update.get("callback_query")

    if not callback:
        return

    sender = callback.get("from", {})
    chat = callback.get("message", {}).get("chat", {})

    sender_id = sender.get("id")
    chat_id = chat.get("id")

    # Hanya akun Telegram yang diizinkan.
    if sender_id != CHAT_ID or chat_id != CHAT_ID:
        acknowledge_callback(callback["id"], "Unauthorized")
        return

    parts = callback.get("data", "").split(":")

    if len(parts) != 3:
        return

    prefix, action, case_id = parts

    if prefix != "ids" or action not in ("block", "ignore"):
        return

    try:
        with open(case_path(case_id), "r", encoding="utf-8") as f:
            case = json.load(f)
    except Exception:
        case = None

    if not case:
        acknowledge_callback(callback["id"], "Case sudah tidak tersedia.")
        return

    if case.get("status") != "PENDING":
        acknowledge_callback(callback["id"], "Case sudah diproses.")
        return

    ip = case.get("src_ip", "unknown")
    message_id = case.get("message_id")

    if action == "block":
        case["status"] = "BLOCK_DISABLED"
        save_case(case)

        acknowledge_callback(
            callback["id"],
            "Pemblokiran Telegram dinonaktifkan. Tidak ada firewall yang diubah."
        )

        if message_id:
            edit_message(
                message_id,
                (
                    "🛡️ ALERT IDS — NOTIFIKASI SAJA\n\n"
                    f"Device    : {case.get('device_id', 'unknown')}\n"
                    f"Source IP : {ip}\n"
                    f"RTT       : {case.get('rtt_ms', 'unknown')} ms\n"
                    f"CPU Load  : {case.get('cpu_load', 'unknown')}%\n\n"
                    "Pemblokiran melalui Telegram dinonaktifkan.\n"
                    "Tidak ada aturan firewall yang diubah."
                )
            )

        log(f"BLOCK_DISABLED case={case_id} ip={ip}")
        return

    # Jangan tandai case sebagai IGNORED sebelum server IDS
    # mengonfirmasi bahwa IGNORE benar-benar diterapkan.
    try:
        result = request_ids_ignore(ip, case_id)
    except Exception as exc:
        log(f"IGNORE_API_FAILED case={case_id} ip={ip} error={exc}")
        acknowledge_callback(
            callback["id"],
            "IGNORE gagal diterapkan. Periksa server IDS."
        )
        return

    case["status"] = "IGNORED"
    case["ignore_action"] = result.get("action")
    save_case(case)

    acknowledge_callback(
        callback["id"],
        "IGNORE berhasil. Auto-block dihentikan untuk siklus ini."
    )

    if message_id:
        edit_message(
            message_id,
            (
                "🟡 AUTO-BLOCK DIABAIKAN\n\n"
                f"Device    : {case.get('device_id', 'unknown')}\n"
                f"Source IP : {ip}\n"
                f"Action    : {result.get('action', 'IGNORED')}\n\n"
                "Auto-block ditahan sampai IDS kembali NORMAL.\n"
                "Jika IP sebelumnya diblokir, blokir telah dilepas."
            )
        )

    log(
        f"IGNORE_APPLIED case={case_id} ip={ip} "
        f"action={result.get('action')}"
    )


def process_pending_cases():

    now = time.time()

    for case in list_cases():

        if case.get("status") != "PENDING":
            continue

        try:
            created = datetime.fromisoformat(
                case["created_at"]
            ).timestamp()
        except Exception:
            created = now

        if now - created < DECISION_TIMEOUT:
            continue

        case["status"] = "EXPIRED_NO_ACTION"
        case["expired_at"] = now
        save_case(case)

        if case.get("message_id"):
            edit_message(
                case["message_id"],
                (
                    "⏰ ALERT IDS — WAKTU RESPONS BERAKHIR\n\n"
                    f"Device    : {case.get('device_id', 'unknown')}\n"
                    f"Source IP : {case.get('src_ip', 'unknown')}\n\n"
                    "Tidak ada respons operator.\n"
                    "Tidak ada pemblokiran otomatis.\n"
                    "Tidak ada perubahan firewall."
                )
            )

        log(
            f"EXPIRED_NO_ACTION "
            f"case={case.get('case_id', 'unknown')} "
            f"ip={case.get('src_ip', 'unknown')}"
        )


def get_updates(offset):

    return telegram_api(
        "getUpdates",
        {
            "offset": offset + 1,
            "timeout": 10,
            "allowed_updates": json.dumps(
                ["callback_query"]
            )
        }
    )


def main():

    os.makedirs(
        STATE_DIR,
        exist_ok=True
    )

    offset = 0

    log("Telegram controller started")

    while True:

        try:

            response = get_updates(
                offset
            )

            for update in response.get(
                "result",
                []
            ):

                offset = update["update_id"]

                process_callback(update)

        except Exception as exc:

            log(
                f"GET_UPDATES_ERROR {exc}"
            )

            time.sleep(3)

        process_pending_cases()

        time.sleep(1)


if __name__ == "__main__":
    main()

