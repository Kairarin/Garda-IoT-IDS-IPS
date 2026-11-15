
"""
Flask IDS Server v7.0 (RF + XGBOOST + IDS STATE MACHINE + RESOURCE MONITORING)
================================================================================
TAMBAHAN dari v6.1:
  [NEW] Import psutil untuk membaca resource Raspberry Pi (CPU%, Memory%)
  [NEW] Fungsi get_pi_resources() — dipanggil setiap update dashboard
  [NEW] Terima field baru dari ESP32: free_heap, heap_usage, cpu_load
  [NEW] Panel SYSTEM RESOURCE di dashboard (bawah IDS DETECTION STATS)
  [NEW] CSV tambahan kolom: esp32_heap_usage, esp32_cpu_load, pi_cpu, pi_memory
        (kolom lama tidak berubah urutan/namanya)

TIDAK DIUBAH:
  arsitektur, Flask routes, async CSV, queue, threading,
  Waitress, health endpoint, /status, /setlabel,
  ML inference workflow, rolling stats, model loading,
  ESP32 payload structure lama, state machine, semua logika IDS

[UPDATE] latency_ms -> rtt_ms (Round-Trip Time)
"""

from flask import Flask, request, jsonify
import pandas as pd
import numpy as np
import os, time, queue, threading, csv, logging, atexit
import ipaddress
import secrets
from datetime import datetime
from datetime import timezone
from collections import deque
import joblib
import warnings
import subprocess
from datetime import datetime


# ─── KONFIGURASI LINGKUNGAN ──────────────────────────────
# Alamat perangkat dan lokasi token TIDAK ditulis di source code.
# Nilai dibaca dari environment variable atau dari file KEY=VALUE
# (default /etc/garda-iot/garda.env, lihat deploy/garda.env.example).
GARDA_ENV_FILE = os.environ.get("GARDA_ENV_FILE", "/etc/garda-iot/garda.env")


def _load_env_file(path):
    values = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    return values


_GARDA_CFG = _load_env_file(GARDA_ENV_FILE)


def cfg(key, default=None):
    """Ambil konfigurasi: environment variable > file garda.env > default."""
    value = os.environ.get(key, _GARDA_CFG.get(key, default))
    if value is None or str(value).strip() == "":
        raise SystemExit(
            f"[CONFIG] {key} belum diatur. Salin deploy/garda.env.example ke "
            f"{GARDA_ENV_FILE} lalu isi nilainya."
        )
    return str(value).strip()


def write_ids_alert(final_status, src_ip, rtt_ms, cpu_load, device_id):
    """Tulis alert ke log file yang dimonitor Wazuh Agent."""
    timestamp = datetime.now().astimezone().strftime('%Y-%m-%dT%H:%M:%S')
    log_line = (
        f"{timestamp} {final_status} "
        f"src_ip={src_ip} "
        f"rtt_ms={rtt_ms} "
        f"cpu_load={cpu_load} "
        f"device={device_id}\n"
    )
    try:
        with open("/var/log/ids_alerts.log", "a") as f:
            f.write(log_line)
    except Exception as e:
        print(f"[LOG ERROR] {e}")

# ─── PSUTIL untuk resource Raspberry Pi ──────────────────
try:
    import psutil
    PSUTIL_READY = True
except ImportError:
    psutil = None
    PSUTIL_READY = False
    print("\033[93m[WARN] psutil tidak terinstall. Jalankan: pip install psutil\033[0m")

warnings.filterwarnings("ignore", category=UserWarning)

logging.getLogger("werkzeug").setLevel(logging.ERROR)
logging.getLogger("waitress").setLevel(logging.ERROR)

app = Flask(__name__)

# ─── CONFIG ──────────────────────────────────────────────
CSV_FILE      = "dataset_realtime_log.csv"
PORT          = 5000

# Registrasi sumber untuk pengujian lab satu klien.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = cfg("GARDA_MODEL_DIR", os.path.join(BASE_DIR, "models"))

IDS_TEST_TOKEN_PATH = cfg(
    "GARDA_IDS_TOKEN_PATH",
    os.path.join(BASE_DIR, ".ids_test_token")
)

# Alamat perangkat lab (diisi di garda.env)
ESP32_IP = cfg("GARDA_ESP32_IP")
PI_IP = cfg("GARDA_PI_IP")
WAZUH_MANAGER_IP = cfg("GARDA_WAZUH_IP")
LAB_ATTACKER_IP = cfg("GARDA_ATTACKER_IP", "10.200.0.2")
IDS_TEST_TTL_SECONDS = 180.0
IDS_TEST_PROTECTED_IPS = frozenset({
    ESP32_IP,          # ESP32
    PI_IP,             # Raspberry Pi IDS
    WAZUH_MANAGER_IP,  # Wazuh Server
})
ids_test_state_lock = threading.Lock()
ids_test_source_ip = None
ids_test_registered_at = 0.0
QUEUE_MAXSIZE = 1000
_ROLLING_N    = 200

current_label = os.environ.get("LABEL_MODE", "normal")

CSV_COLUMNS = [
    # ── Kolom lama (urutan tidak berubah) ─────────────
    "timestamp_unix", "timestamp_esp", "device_id",
    "interval_ms", "rtt_ms", "jitter_ms", "packet_rate",
    "label_aktual", "prediksi_rf", "prediksi_xgb",
    "temporary_status", "final_status",
    "attack_counter", "recovery_counter",
    # ── Kolom baru resource monitoring (ditambahkan di akhir) ──
    "esp32_heap_usage",   # heap usage ESP32 dalam persen (%)
    "esp32_cpu_load",     # estimasi CPU load ESP32 dalam persen (%)
    "pi_cpu",             # CPU usage Raspberry Pi dalam persen (%)
    "pi_memory",          # Memory usage Raspberry Pi dalam persen (%)
    # ── Network Quality (baru v8) — di bagian akhir ──
    "http_success_rate",
    "communication_loss",
    "timeout_rate",
    "network_health",
]

FEATURE_COLS = ["interval_ms", "rtt_ms", "jitter_ms", "packet_rate"]

# ─── ANSI ────────────────────────────────────────────────
R   = "\033[0m"
BO  = "\033[1m"
GR  = "\033[92m"
YE  = "\033[93m"
RE  = "\033[91m"
CY  = "\033[96m"
BL  = "\033[94m"
MA  = "\033[95m"
WHI = "\033[97m"

# ─── RESOURCE MONITORING STATE ───────────────────────────
_resource_lock    = threading.Lock()
_last_resource    = {
    "esp32_heap_usage" : 0.0,
    "esp32_cpu_load"   : 0.0,
    "pi_cpu"           : 0.0,
    "pi_memory"        : 0.0,
}

def get_pi_resources():
    """Baca CPU dan Memory Raspberry Pi via psutil secara non-blocking."""
    if not PSUTIL_READY:
        return 0.0, 0.0
    try:
        cpu_pct = psutil.cpu_percent(interval=None)
        mem     = psutil.virtual_memory()
        mem_pct = mem.percent
        return round(cpu_pct, 1), round(mem_pct, 1)
    except Exception:
        return 0.0, 0.0

if PSUTIL_READY:
    psutil.cpu_percent(interval=0.1)

# ─── LOAD MODEL ──────────────────────────────────────────
print(f"\n{CY}{'='*60}{R}")
print(f"{BO}  MEMUAT MODEL MACHINE LEARNING...{R}")
print(f"{CY}{'='*60}{R}")
try:
    model_rf  = joblib.load(os.path.join(MODEL_DIR, "model_rf.pkl"))
    model_xgb = joblib.load(os.path.join(MODEL_DIR, "model_xgb.pkl"))
    encoder   = joblib.load(os.path.join(MODEL_DIR, "label_encoder.pkl"))
    ML_READY  = True
    print(f"  {GR}✅ Random Forest : Siap!{R}")
    print(f"  {GR}✅ XGBoost       : Siap!{R}")
    print(f"  {GR}✅ Label Encoder : Siap!{R}")
except Exception as e:
    model_rf = model_xgb = encoder = None
    ML_READY = False
    print(f"  {RE}❌ Gagal memuat model: {e}{R}")
    print(f"  {YE}   Pastikan model_rf.pkl, model_xgb.pkl, label_encoder.pkl ada.{R}")
print(f"{CY}{'='*60}{R}\n")

# ─── IN-MEMORY COUNTERS ───────────────────────────────────
_counters      = {"total": 0, "normal": 0, "dos": 0}
_counters_lock = threading.Lock()

_display_counters = {"total": 0, "normal": 0, "dos": 0}
_display_lock     = threading.Lock()

_rolling = {
    "normal": {k: deque(maxlen=_ROLLING_N) for k in FEATURE_COLS},
    "dos"   : {k: deque(maxlen=_ROLLING_N) for k in FEATURE_COLS},
}
_rolling_lock = threading.Lock()

# ─── ASYNC CSV WRITER ────────────────────────────────────
write_queue = queue.Queue(maxsize=QUEUE_MAXSIZE)

def csv_writer_thread():
    while True:
        try:
            row = write_queue.get(timeout=2)
        except queue.Empty:
            continue

        try:
            if row is None:
                return

            file_exists = os.path.exists(CSV_FILE)

            if file_exists and os.path.getsize(CSV_FILE) > 0:
                with open(CSV_FILE, "r", newline="", encoding="utf-8") as f:
                    existing_header = next(csv.reader(f), None)

                if existing_header != CSV_COLUMNS:
                    raise ValueError(
                        f"CSV header mismatch: expected {len(CSV_COLUMNS)} "
                        f"columns, found {len(existing_header or [])}. "
                        "Writing stopped to protect existing data."
                    )

            with open(CSV_FILE, "a", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
                if not file_exists or os.path.getsize(CSV_FILE) == 0:
                    writer.writeheader()
                writer.writerow(row)

        except Exception:
            logging.exception("[CSV WRITER ERROR] Gagal menulis dataset")

        finally:
            write_queue.task_done()

csv_thread = threading.Thread(
    target=csv_writer_thread,
    name="csv-writer",
    daemon=True
)
csv_thread.start()

def shutdown_csv_writer():
    logging.info("[CSV WRITER] Menunggu antrean selesai...")
    write_queue.put(None)
    write_queue.join()
    csv_thread.join(timeout=10)

    if csv_thread.is_alive():
        logging.error("[CSV WRITER] Thread belum berhenti setelah timeout")
    else:
        logging.info("[CSV WRITER] Shutdown selesai")

atexit.register(shutdown_csv_writer)

# ═══════════════════════════════════════════════════════════
#  IDS STATE MACHINE — GLOBAL VARIABLES
# ═══════════════════════════════════════════════════════════
IDS_STATE            = "NORMAL"
IDS_ATTACK_COUNTER   = 0
IDS_RECOVERY_COUNTER = 0
IDS_CONFIRM_SHOWN    = False

ATTACK_CONFIRM_THRESHOLD  = 10
RECOVERY_NORMAL_THRESHOLD = 5

ids_lock = threading.Lock()

# ─── IPS FIREWALL CONFIGURATION ──────────────────────────
IPS_ENABLED = True

IPS_NFT_TABLE = "ids_ips_auto"
IPS_NFT_SET = "blocked_attackers"

IPS_ATTACKER_IP = LAB_ATTACKER_IP
IPS_PROTECTED_IP = ESP32_IP

IPS_BLOCK_SECONDS = 60
IPS_COOLDOWN_SECONDS = 300

ips_lock = threading.Lock()
ips_block_active = False
ips_cooldown_until = 0.0
ips_last_action = "IDLE"

# Counter IPS terpisah dari counter IDS.
IPS_ATTACK_THRESHOLD = 20
IPS_ATTACK_COUNTER = 0
IPS_BLOCK_TRIGGERED = False
IPS_IGNORE_ACTIVE = False
IPS_IGNORE_CASE_ID = None
ips_counter_lock = threading.Lock()


def ips_get_set_status(set_name):
    """Periksa keberadaan IP penyerang dalam nftables set."""
    try:
        result = subprocess.run(
            [
                "/usr/bin/sudo", "-n", "/usr/sbin/nft",
                "get", "element", "inet", IPS_NFT_TABLE,
                set_name, "{", IPS_ATTACKER_IP, "}"
            ],
            capture_output=True,
            text=True,
            timeout=3,
            check=False
        )

        if result.returncode == 0:
            return True

        error = result.stderr.lower()

        if (
            "could not process rule: no such file or directory" in error
            or "element does not exist" in error
            or "element not found" in error
        ):
            return False

        logging.error(
            "[IPS] Gagal memeriksa set %s: %s",
            set_name, result.stderr.strip()
        )
        return None

    except Exception:
        logging.exception("[IPS] Exception saat memeriksa nftables")
        return None


def ips_get_block_status():
    """Periksa apakah IP penyerang sedang diblokir."""
    return ips_get_set_status(IPS_NFT_SET)


def ips_activate_block(src_ip):
    """Blokir penyerang selama 60 detik dan terapkan cooldown 300 detik."""
    global ips_last_action

    if not IPS_ENABLED or src_ip != IPS_ATTACKER_IP:
        return False

    with ips_lock:
        # Cek ulang di dalam lock agar IGNORE tidak kalah race
        # dengan proses auto-block yang sedang berjalan.
        with ips_counter_lock:
            if IPS_IGNORE_ACTIVE:
                ips_last_action = "IGNORED"
                return False

        block_status = ips_get_block_status()

        if block_status is None:
            ips_last_action = "ERROR_CHECK_BLOCK"
            return False

        if block_status:
            ips_last_action = "ALREADY_BLOCKED"
            return False

        cooldown_status = ips_get_set_status("cooldown_guard")

        if cooldown_status is None:
            ips_last_action = "ERROR_CHECK_COOLDOWN"
            return False

        if cooldown_status:
            ips_last_action = "COOLDOWN_ACTIVE"
            logging.info(
                "[IPS] Blokir tidak diulang. Cooldown masih aktif untuk %s",
                src_ip
            )
            return False

        nft_batch = (
            f"add element inet {IPS_NFT_TABLE} {IPS_NFT_SET} "
            f"{{ {src_ip} timeout {IPS_BLOCK_SECONDS}s }}\n"
            f"add element inet {IPS_NFT_TABLE} cooldown_guard "
            f"{{ {src_ip} timeout "
            f"{IPS_BLOCK_SECONDS + IPS_COOLDOWN_SECONDS}s }}\n"
        )

        try:
            result = subprocess.run(
                [
                    "/usr/bin/sudo", "-n", "/usr/sbin/nft",
                    "-f", "-"
                ],
                input=nft_batch,
                capture_output=True,
                text=True,
                timeout=5,
                check=False
            )

            if result.returncode != 0:
                ips_last_action = "ERROR_BLOCK"
                logging.error(
                    "[IPS] Gagal mengaktifkan blokir: %s",
                    result.stderr.strip()
                )
                return False

            ips_last_action = "BLOCKED"
            logging.warning(
                "[IPS] IP %s diblokir menuju %s selama %s detik. "
                "Cooldown %s detik dimulai setelah blokir berakhir.",
                src_ip,
                IPS_PROTECTED_IP,
                IPS_BLOCK_SECONDS,
                IPS_COOLDOWN_SECONDS
            )
            return True

        except Exception:
            ips_last_action = "ERROR_EXCEPTION"
            logging.exception("[IPS] Exception saat mengaktifkan blokir")
            return False


def ips_process_state(final_st, src_ip):
    """
    Hitung hanya DOS ATTACK IN PROGRESS.
    Recovery mempertahankan counter.
    NORMAL mereset counter dan siklus pemblokiran.
    """
    global IPS_ATTACK_COUNTER, IPS_BLOCK_TRIGGERED
    global IPS_IGNORE_ACTIVE, IPS_IGNORE_CASE_ID, ips_last_action

    should_block = False

    with ips_counter_lock:
        if final_st == "NORMAL":
            if IPS_ATTACK_COUNTER != 0 or IPS_BLOCK_TRIGGERED:
                logging.info(
                    "[IPS] Siklus selesai. Counter direset dari %s ke 0.",
                    IPS_ATTACK_COUNTER
                )

            IPS_ATTACK_COUNTER = 0
            IPS_BLOCK_TRIGGERED = False
            IPS_IGNORE_ACTIVE = False
            IPS_IGNORE_CASE_ID = None

            if ips_last_action.startswith("IGNORED"):
                ips_last_action = "IDLE"

            logging.info("[IPS] IGNORE direset. Siklus baru diizinkan.")
            return

        if final_st != "DOS ATTACK IN PROGRESS":
            return

        if IPS_ATTACK_COUNTER < IPS_ATTACK_THRESHOLD:
            IPS_ATTACK_COUNTER += 1

            logging.info(
                "[IPS] Attack progress counter: %s/%s",
                IPS_ATTACK_COUNTER,
                IPS_ATTACK_THRESHOLD
            )

        # IDS tetap menghitung dan mendeteksi serangan.
        # Namun IPS tidak melakukan auto-block selama IGNORE aktif.
        if IPS_IGNORE_ACTIVE:
            IPS_BLOCK_TRIGGERED = True
            return

        if (
            IPS_ATTACK_COUNTER >= IPS_ATTACK_THRESHOLD
            and not IPS_BLOCK_TRIGGERED
            and IPS_ENABLED
            and src_ip == IPS_ATTACKER_IP
        ):
            # Tandai sebelum menjalankan nftables agar tidak dipanggil
            # berulang kali oleh request yang datang bersamaan.
            IPS_BLOCK_TRIGGERED = True
            should_block = True

    if should_block:
        logging.warning(
            "[IPS] Threshold %s/%s tercapai. Memulai Auto Block untuk %s.",
            IPS_ATTACK_THRESHOLD,
            IPS_ATTACK_THRESHOLD,
            src_ip
        )

        block_result = ips_activate_block(src_ip)

        with ips_lock:
            action = ips_last_action

        # Keberhasilan, blokir yang sudah aktif, atau cooldown aktif
        # dianggap sudah ditangani untuk siklus serangan ini.
        terminal_actions = {
            "BLOCKED",
            "ALREADY_BLOCKED",
            "COOLDOWN_ACTIVE",
            "IGNORED",
            "IGNORED_UNBLOCKED"
        }

        if not block_result and action not in terminal_actions:
            with ips_counter_lock:
                IPS_BLOCK_TRIGGERED = False

            logging.error(
                "[IPS] Auto Block gagal (%s). "
                "Percobaan ulang diizinkan pada data serangan berikutnya.",
                action
            )


# ─── HELPER ML ───────────────────────────────────────────
def normalize_label(x):
    if x is None:
        return "unknown"
    if isinstance(x, (np.integer, np.int64, int)):
        try:
            return str(encoder.inverse_transform([int(x)])[0]).strip().lower()
        except Exception:
            return str(x)
    return str(x).strip().lower()

def predict_rf(X_df):
    return normalize_label(model_rf.predict(X_df)[0])

def predict_xgb(X_df):
    return normalize_label(model_xgb.predict(X_df)[0])

# ─── TEMPORARY STATUS ────────────────────────────────────
def get_temporary_status(rf_label, xgb_label):
    if rf_label == "normal" and xgb_label == "normal":
        return "NORMAL"
    elif rf_label == "dos" and xgb_label == "dos":
        return "DOS INDICATED"
    else:
        return "SUSPICIOUS"

# ─── IDS STATE MACHINE ───────────────────────────────────
def update_ids_state(temp_status):
    global IDS_STATE, IDS_ATTACK_COUNTER, IDS_RECOVERY_COUNTER, IDS_CONFIRM_SHOWN

    with ids_lock:
        # Model tidak sepakat: jangan anggap sebagai bukti serangan.
        if temp_status == "SUSPICIOUS":
            if IDS_STATE == "UNDER_MONITORING":
                IDS_ATTACK_COUNTER = 0
                IDS_STATE = "NORMAL"
                IDS_CONFIRM_SHOWN = False
                return "SUSPICIOUS"

            if IDS_STATE == "RECOVERY_MONITORING":
                # Recovery harus terdiri dari NORMAL berturut-turut.
                IDS_RECOVERY_COUNTER = 0
                return "RECOVERY MONITORING"

            # Jika serangan sudah terkonfirmasi, pertahankan state.
            # Namun sampel ini tidak menambah counter IPS.
            return "SUSPICIOUS"

        if temp_status == "NORMAL":
            if IDS_STATE == "NORMAL":
                IDS_ATTACK_COUNTER = 0
                return "NORMAL"

            elif IDS_STATE == "UNDER_MONITORING":
                IDS_ATTACK_COUNTER = 0
                IDS_STATE = "NORMAL"
                return "NORMAL"

            elif IDS_STATE in ("CONFIRM_DOS_ATTACK", "DOS_ATTACK"):
                IDS_STATE = "RECOVERY_MONITORING"
                IDS_RECOVERY_COUNTER = 1
                IDS_ATTACK_COUNTER = 0
                return "RECOVERY MONITORING"

            elif IDS_STATE == "RECOVERY_MONITORING":
                IDS_RECOVERY_COUNTER += 1
                if IDS_RECOVERY_COUNTER >= RECOVERY_NORMAL_THRESHOLD:
                    IDS_STATE = "NORMAL"
                    IDS_ATTACK_COUNTER = 0
                    IDS_RECOVERY_COUNTER = 0
                    IDS_CONFIRM_SHOWN = False
                    return "NORMAL"
                return "RECOVERY MONITORING"

        elif temp_status == "DOS INDICATED":
            IDS_RECOVERY_COUNTER = 0

            if IDS_STATE == "NORMAL":
                IDS_STATE = "UNDER_MONITORING"
                IDS_ATTACK_COUNTER = 1
                return "UNDER MONITORING"

            elif IDS_STATE == "UNDER_MONITORING":
                IDS_ATTACK_COUNTER += 1
                if IDS_ATTACK_COUNTER >= ATTACK_CONFIRM_THRESHOLD:
                    if not IDS_CONFIRM_SHOWN:
                        IDS_STATE = "CONFIRM_DOS_ATTACK"
                        IDS_CONFIRM_SHOWN = True
                        return "CONFIRMED DOS ATTACK"
                    else:
                        IDS_STATE = "DOS_ATTACK"
                        return "DOS ATTACK IN PROGRESS"
                return "UNDER MONITORING"

            elif IDS_STATE == "CONFIRM_DOS_ATTACK":
                IDS_STATE = "DOS_ATTACK"
                IDS_ATTACK_COUNTER += 1
                return "DOS ATTACK IN PROGRESS"

            elif IDS_STATE == "DOS_ATTACK":
                IDS_ATTACK_COUNTER += 1
                return "DOS ATTACK IN PROGRESS"

            elif IDS_STATE == "RECOVERY_MONITORING":
                IDS_STATE = "DOS_ATTACK"
                IDS_RECOVERY_COUNTER = 0
                IDS_ATTACK_COUNTER += 1
                return "DOS ATTACK IN PROGRESS"

    return "NORMAL"

# ─── WARNA STATE ─────────────────────────────────────────
def color_temp(s):
    m = {
        "NORMAL"       : f"{GR}🟢 NORMAL{R}",
        "DOS INDICATED": f"{RE}🔴 DOS INDICATED{R}",
        "SUSPICIOUS"   : f"{YE}🟡 SUSPICIOUS{R}",
    }
    return m.get(s, f"{YE}{s}{R}")

def color_final(s):
    m = {
        "NORMAL"               : f"{GR}🟢 NORMAL{R}",
        "UNDER MONITORING"     : f"{YE}🟡 UNDER MONITORING{R}",
        "CONFIRMED DOS ATTACK" : f"{RE}{BO}🚨 CONFIRMED DOS ATTACK{R}",
        "DOS ATTACK IN PROGRESS": f"{RE}{BO}🔴 DOS ATTACK IN PROGRESS{R}",
        "RECOVERY MONITORING"  : f"{CY}🔄 RECOVERY MONITORING{R}",
        "ML NOT READY"         : f"{MA}❌ ML NOT READY{R}",
    }
    return m.get(s, f"{YE}{s}{R}")

def color_rf(label):
    if label == "normal": return f"{GR}🟢 NORMAL{R}"
    if label == "dos"   : return f"{RE}🔴 DOS{R}"
    return f"{YE}🟡 ?{R}"

def color_xgb(label):
    if label == "normal": return f"{GR}🟢 NORMAL{R}"
    if label == "dos"   : return f"{RE}🔴 DOS{R}"
    return f"{YE}🟡 ?{R}"

def color_res(val):
    if val >= 85.0: return f"{RE}{BO}{val:.1f}%{R}"
    if val >= 60.0: return f"{YE}{val:.1f}%{R}"
    return f"{YE}{val:.1f}%{R}"

def color_net_health(val):
    """Warna terbalik untuk Network Health: tinggi = bagus (hijau)"""
    if val >= 90.0:
        return f"{GR}{val:.1f}%{R}"
    if val >= 70.0:
        return f"{YE}{val:.1f}%{R}"
    return f"{RE}{BO}{val:.1f}%{R}"

def color_net_bad(val):
    """Untuk loss/timeout: rendah = bagus"""
    if val <= 5.0:
        return f"{YE}{val:.1f}%{R}"
    if val <= 20.0:
        return f"{YE}{val:.1f}%{R}"
    return f"{RE}{BO}{val:.1f}%{R}"

# ─── DASHBOARD ───────────────────────────────────────────
def _strip_ansi(s):
    import re
    return re.sub(r'\x1b\[[0-9;]*m', '', str(s))

def _vlen(s):
    try:
        from wcwidth import wcswidth
        w = wcswidth(_strip_ansi(s))
        return w if w >= 0 else len(_strip_ansi(s))
    except ImportError:
        return len(_strip_ansi(s))

def _pad(s, width): return str(s) + " " * max(0, width - _vlen(s))
def _fit(s, width):
    s = str(s)
    if _vlen(s) <= width: return s
    return _strip_ansi(s)[:max(0, width - 1)] + "…"

def _bar(current, total, width=10, filled="█", empty="░"):
    total   = max(1, int(total))
    current = max(0, min(int(current), total))
    filled_n = round(width * current / total)
    return f"[{filled * filled_n}{empty * (width - filled_n)}] {current}/{total}"

def print_ids_box(waktu, interval_ms, rtt_ms, jitter_ms, packet_rate,
                  rf_label, xgb_label, temp_status, final_status_str,
                  attack_ctr, recovery_ctr, device_id="unknown",
                  esp32_heap=0.0, esp32_cpu=0.0, pi_cpu=0.0, pi_mem=0.0,
                  http_success_rate=100.0, communication_loss=0.0,
                  timeout_rate=0.0, network_health=100.0):

    import shutil

    with _display_lock:
        _display_counters["total"] += 1
        fs = str(final_status_str).strip().upper()
        if fs == "NORMAL":
            _display_counters["normal"] += 1
        elif fs not in ("ML NOT READY", "RECOVERY MONITORING"):
            _display_counters["dos"] += 1
        out_total  = _display_counters["total"]
        out_normal = _display_counters["normal"]
        out_dos    = _display_counters["dos"]

    left_w  = 60
    mid_w   = 28
    right_w = 31

    term_w = shutil.get_terminal_size((129, 30)).columns
    if term_w < left_w + mid_w + right_w + 10:
        spare = max(0, term_w - 10)
        ratio = left_w + mid_w + right_w
        left_w  = max(48, round(spare * left_w  / ratio))
        mid_w   = max(24, round(spare * mid_w   / ratio))
        right_w = max(28, spare - left_w - mid_w)

    def top_border(): print(f"╔{'═'*(left_w+2)}╦{'═'*(mid_w+2)}╦{'═'*(right_w+2)}╗")
    def mid_border(): print(f"╠{'═'*(left_w+2)}╬{'═'*(mid_w+2)}╬{'═'*(right_w+2)}╣")
    def bot_border(): print(f"╚{'═'*(left_w+2)}╩{'═'*(mid_w+2)}╩{'═'*(right_w+2)}╝")
    def row(a="", b="", c=""):
        print(f"║ {_pad(_fit(a, left_w), left_w)} ║ {_pad(_fit(b, mid_w), mid_w)} ║ {_pad(_fit(c, right_w), right_w)} ║")

    left_rows = [
        f"{BO}{CY}TELEMETRY{R}",
        f"{YE}├{R} Interval       : {WHI}{interval_ms} ms{R}",
        f"{YE}├{R} RTT            : {WHI}{rtt_ms} ms{R}",
        f"{YE}├{R} Jitter         : {WHI}{jitter_ms} ms{R}",
        f"{YE}└{R} Packet Rate    : {WHI}{packet_rate:.1f} pps{R}",
        "",
        f"{BO}{CY}MACHINE LEARNING{R}",
        f"{YE}├{R} Random Forest  : {color_rf(rf_label)}",
        f"{YE}└{R} XGBoost        : {color_xgb(xgb_label)}",
        "",
        f"{BO}{CY}STATE MACHINE{R}",
        f"{YE}├{R} Temporary State : {color_temp(temp_status)}",
        f"{YE}├{R} Final State     : {color_final(final_status_str)}",
        f"{YE}├{R} Attack Counter  : {_bar(attack_ctr, ATTACK_CONFIRM_THRESHOLD)}",
        f"{YE}└{R} Recovery Counter: {_bar(recovery_ctr, RECOVERY_NORMAL_THRESHOLD)}",
    ]

    # ── Panel Tengah: IDS HEALTH + NETWORK QUALITY (baru) ──
    mid_rows = [
        f"{BO}{CY}IDS HEALTH{R}",
        f"{YE}├{R} ML Status       : {GR}READY{R}" if ML_READY else f"{YE}├{R} ML Status       : {RE}NOT READY{R}",
        f"{YE}├{R} Random Forest   : {GR}ACTIVE{R}" if ML_READY else f"{YE}├{R} Random Forest   : {RE}INACTIVE{R}",
        f"{YE}├{R} XGBoost         : {GR}ACTIVE{R}" if ML_READY else f"{YE}├{R} XGBoost         : {RE}INACTIVE{R}",
        f"{YE}├{R} CSV Writer      : {GR}ACTIVE{R}",
            f"{YE}└{R} Server          : {GR}ONLINE{R}",
        "",
        # ── NETWORK QUALITY panel baru, tepat di bawah IDS HEALTH ──
        f"{BO}{BL}NETWORK QUALITY{R}",
        f"{YE}├{R} {'HTTP Success':<15}: {color_net_health(http_success_rate)}",
        f"{YE}├{R} {'Comm Loss':<15}: {color_net_bad(communication_loss)}",
        f"{YE}├{R} {'Timeout Rate':<15}: {color_net_bad(timeout_rate)}",
        f"{YE}└{R} {'Net Health':<15}: {color_net_health(network_health)}",
    ]

    normal_rate = (out_normal / out_total * 100.0) if out_total else 0.0
    dos_rate    = (out_dos    / out_total * 100.0) if out_total else 0.0
    right_rows = [
        f"{BO}{CY}IDS DETECTION STATS{R}",
        f"{YE}├{R} Processed Data   : {WHI}{out_total}{R}",
        f"{YE}├{R} Detected Normal  : {GR}{out_normal}{R}",
        f"{YE}├{R} Detected DoS     : {RE}{out_dos}{R}",
        f"{YE}├{R} Normal Rate      : {WHI}{normal_rate:.1f}%{R}",
        f"{YE}└{R} DoS Rate         : {WHI}{dos_rate:.1f}%{R}",
        "",
        f"{BO}{BL}SYSTEM RESOURCE{R}",
        f"{YE}├{R} ESP32 CPU        : {color_res(esp32_cpu)}",
        f"{YE}├{R} ESP32 Memory     : {color_res(esp32_heap)}",
        f"{YE}├{R} Pi CPU           : {color_res(pi_cpu)}",
        f"{YE}└{R} Pi Memory        : {color_res(pi_mem)}",
    ]

    header_left  = f"{BO}{CY} STATEFUL IDS MONITOR{R}"
    header_mid   = f"{CY}LAST UPDATE:{R} {WHI}{waktu}{R}"
    header_right = f"{YE}DEVICE:{R} {WHI}{device_id}{R}"
    sub_left     = f"{MA}LIVE TELEMETRY → ML → STATEFUL IDS{R}"

    top_border()
    row(header_left, header_mid, header_right)
    row(sub_left)
    mid_border()

    max_rows = max(len(left_rows), len(mid_rows), len(right_rows))
    for i in range(max_rows):
        a = left_rows[i]  if i < len(left_rows)  else ""
        b = mid_rows[i]   if i < len(mid_rows)   else ""
        c = right_rows[i] if i < len(right_rows) else ""
        row(a, b, c)

    bot_border()

# ─── ENDPOINT /health ────────────────────────────────────
@app.route("/register-test-client", methods=["POST"])
def register_test_client():
    supplied_token = request.headers.get("X-IDS-Test-Token", "")

    try:
        with open(IDS_TEST_TOKEN_PATH, "r", encoding="utf-8") as f:
            expected_token = f.read().strip()
    except OSError:
        expected_token = ""

    if (
        not expected_token
        or not secrets.compare_digest(supplied_token, expected_token)
    ):
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    raw_ip = request.remote_addr or ""

    try:
        source = ipaddress.ip_address(raw_ip)
    except ValueError:
        return jsonify({"ok": False, "error": "invalid source IP"}), 400

    if source != ipaddress.ip_address(LAB_ATTACKER_IP):
        return jsonify({"ok": False, "error": "outside lab subnet"}), 403

    source_ip = str(source)

    if source_ip in IDS_TEST_PROTECTED_IPS:
        return jsonify({"ok": False, "error": "protected IP"}), 403

    global ids_test_source_ip, ids_test_registered_at

    with ids_test_state_lock:
        ids_test_source_ip = source_ip
        ids_test_registered_at = time.monotonic()

    return jsonify({
        "ok": True,
        "attacker_ip": source_ip,
        "expires_in": int(IDS_TEST_TTL_SECONDS)
    }), 200


@app.route("/health", methods=["GET"])
def health():
    return "ok", 200

# ─── ENDPOINT /data ──────────────────────────────────────
@app.route("/data", methods=["POST"])
def terima_data():
    global current_label
    server_time = time.time()

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error"}), 400

    device_id   = data.get("device_id",   "unknown")
    esp_ts      = data.get("timestamp",    0)
    interval_ms = int(data.get("interval_ms",  0))
    rtt_ms      = int(data.get("rtt_ms",       0))
    jitter_ms   = int(data.get("jitter_ms",    0))
    packet_rate = float(data.get("packet_rate",  0.0))

    esp32_heap_usage = float(data.get("heap_usage", 0.0))
    esp32_cpu_load   = float(data.get("cpu_load",   0.0))

    http_success_rate  = float(data.get("http_success_rate",  100.0))
    communication_loss = float(data.get("communication_loss",   0.0))
    timeout_rate       = float(data.get("timeout_rate",         0.0))
    network_health     = float(data.get("network_health",      100.0))

    pred_rf     = "unknown"
    pred_xgb    = "unknown"
    temp_status = "UNKNOWN"
    final_st    = "ML NOT READY"

    if ML_READY:
        X_live = pd.DataFrame([{
            "interval_ms": interval_ms,
            "rtt_ms"     : rtt_ms,
            "jitter_ms"  : jitter_ms,
            "packet_rate": packet_rate
        }], columns=FEATURE_COLS)

        pred_rf     = predict_rf(X_live)
        pred_xgb    = predict_xgb(X_live)
        temp_status = get_temporary_status(pred_rf, pred_xgb)
        final_st    = update_ids_state(temp_status)

    src_ip = "unknown"

    # Tulis ke log IDS jika ada perubahan state penting
    if final_st in ("CONFIRMED DOS ATTACK", "DOS ATTACK IN PROGRESS",
                    "RECOVERY MONITORING", "UNDER MONITORING"):
        # Gunakan IP klien penguji yang diregistrasikan secara sah.
        # Tanpa registrasi aktif, jangan salah menganggap ESP32 sebagai penyerang.
        with ids_test_state_lock:
            registered_ip = ids_test_source_ip
            registered_at = ids_test_registered_at

        if (
            registered_ip
            and time.monotonic() - registered_at <= IDS_TEST_TTL_SECONDS
        ):
            src_ip = registered_ip
        else:
            src_ip = "unknown"

        write_ids_alert(
            final_st.replace(" ", "_"),
            src_ip,
            rtt_ms,
            round(esp32_cpu_load, 1),
            device_id
        )

    # Evaluasi counter IPS berdasarkan state IDS terakhir.
    ips_process_state(final_st, src_ip)

    with _counters_lock:
        _counters["total"] += 1
        if current_label in _counters:
            _counters[current_label] += 1

    lk = current_label if current_label in _rolling else "normal"
    with _rolling_lock:
        for k, v in zip(FEATURE_COLS, [interval_ms, rtt_ms, jitter_ms, packet_rate]):
            _rolling[lk][k].append(v)

    with ids_lock:
        atk_ctr = IDS_ATTACK_COUNTER
        rec_ctr = IDS_RECOVERY_COUNTER

    pi_cpu_now, pi_mem_now = get_pi_resources()

    with _resource_lock:
        _last_resource["esp32_heap_usage"] = esp32_heap_usage
        _last_resource["esp32_cpu_load"]   = esp32_cpu_load
        _last_resource["pi_cpu"]           = pi_cpu_now
        _last_resource["pi_memory"]        = pi_mem_now

    waktu = datetime.fromtimestamp(server_time).strftime("%H:%M:%S")
    print_ids_box(
        waktu, interval_ms, rtt_ms, jitter_ms, packet_rate,
        pred_rf, pred_xgb, temp_status, final_st,
        atk_ctr, rec_ctr, device_id=device_id,
        esp32_heap=esp32_heap_usage, esp32_cpu=esp32_cpu_load,
        pi_cpu=pi_cpu_now, pi_mem=pi_mem_now,
    )

    row = {
        "timestamp_unix"   : round(server_time, 3),
        "timestamp_esp"    : int(esp_ts),
        "device_id"        : str(device_id),
        "interval_ms"      : interval_ms,
        "rtt_ms"           : rtt_ms,
        "jitter_ms"        : jitter_ms,
        "packet_rate"      : round(packet_rate, 2),
        "label_aktual"     : current_label,
        "prediksi_rf"      : pred_rf,
        "prediksi_xgb"     : pred_xgb,
        "temporary_status" : temp_status,
        "final_status"     : final_st,
        "attack_counter"   : atk_ctr,
        "recovery_counter" : rec_ctr,
        "esp32_heap_usage" : round(esp32_heap_usage, 1),
        "esp32_cpu_load"   : round(esp32_cpu_load,   1),
        "pi_cpu"           : round(pi_cpu_now,        1),
        "pi_memory"        : round(pi_mem_now,        1),
        "http_success_rate"  : round(http_success_rate,  1),
        "communication_loss" : round(communication_loss, 1),
        "timeout_rate"       : round(timeout_rate,       1),
        "network_health"     : round(network_health,     1),
    }
    try:
        write_queue.put_nowait(row)
    except queue.Full:
        pass

    return jsonify({
        "status"           : "ok",
        "rf_detect"        : pred_rf,
        "xgb_detect"       : pred_xgb,
        "temporary_status" : temp_status,
        "final_status"     : final_st,
        "attack_counter"   : atk_ctr,
        "recovery_counter" : rec_ctr,
    }), 200

# ─── ENDPOINT /setlabel ──────────────────────────────────
@app.route("/setlabel", methods=["POST"])
def set_label():
    global current_label

    supplied_token = request.headers.get("X-IDS-Test-Token", "")

    try:
        with open(IDS_TEST_TOKEN_PATH, "r", encoding="utf-8") as f:
            expected_token = f.read().strip()
    except OSError:
        expected_token = ""

    if (
        not expected_token
        or not secrets.compare_digest(supplied_token, expected_token)
    ):
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("label"), str):
        return jsonify({"error": "JSON dengan field label wajib diisi"}), 400

    new_label = data["label"].strip().lower()
    if new_label not in ["normal", "dos"]:
        return jsonify({"error": "Label harus 'normal' atau 'dos'"}), 400

    current_label = new_label
    color = GR if new_label == "normal" else RE
    print(f"\n{color}{BO}{'═'*50}{R}")
    print(f"{color}{BO}  📌 LABEL MODE → {new_label.upper()}{R}")
    print(f"{color}{BO}{'═'*50}{R}\n")
    return jsonify({"status": "ok", "label": current_label}), 200

# ─── ENDPOINT /ignore ─────────────────────────────────────
@app.route("/ignore", methods=["POST"])
def ignore_ips_attack():
    global IPS_IGNORE_ACTIVE, IPS_IGNORE_CASE_ID
    global IPS_BLOCK_TRIGGERED, ips_last_action

    supplied_token = request.headers.get("X-IDS-Test-Token", "")

    try:
        with open(IDS_TEST_TOKEN_PATH, "r", encoding="utf-8") as f:
            expected_token = f.read().strip()
    except OSError:
        expected_token = ""

    if (
        not expected_token
        or not secrets.compare_digest(supplied_token, expected_token)
    ):
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"ok": False, "error": "invalid JSON"}), 400

    src_ip = str(data.get("src_ip", "")).strip()
    case_id = str(data.get("case_id", "")).strip()[:128]

    if src_ip != IPS_ATTACKER_IP:
        return jsonify({"ok": False, "error": "attacker IP not allowed"}), 403

    with ids_lock:
        current_state = IDS_STATE

    active_states = {
        "UNDER_MONITORING",
        "CONFIRM_DOS_ATTACK",
        "DOS_ATTACK",
        "RECOVERY_MONITORING",
    }

    if current_state not in active_states:
        return jsonify({
            "ok": False,
            "error": "no active attack cycle",
            "ids_state": current_state
        }), 409

    # Aktifkan IGNORE terlebih dahulu agar tidak ada auto-block
    # baru ketika proses penghapusan elemen nftables berjalan.
    with ips_counter_lock:
        IPS_IGNORE_ACTIVE = True
        IPS_IGNORE_CASE_ID = case_id
        IPS_BLOCK_TRIGGERED = True

    with ips_lock:
        block_status = ips_get_block_status()
        cooldown_status = ips_get_set_status("cooldown_guard")

        if block_status is None or cooldown_status is None:
            ips_last_action = "ERROR_IGNORE_CHECK"
            logging.error("[IPS] IGNORE aktif, tetapi pemeriksaan nftables gagal.")
            return jsonify({
                "ok": False,
                "error": "cannot verify nftables state; IGNORE remains active"
            }), 500

        commands = []

        if block_status:
            commands.append(
                f"delete element inet {IPS_NFT_TABLE} "
                f"{IPS_NFT_SET} {{ {src_ip} }}"
            )

        if cooldown_status:
            commands.append(
                f"delete element inet {IPS_NFT_TABLE} "
                f"cooldown_guard {{ {src_ip} }}"
            )

        if commands:
            try:
                result = subprocess.run(
                    [
                        "/usr/bin/sudo", "-n", "/usr/sbin/nft",
                        "-f", "-"
                    ],
                    input="\n".join(commands) + "\n",
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False
                )

                if result.returncode != 0:
                    ips_last_action = "ERROR_IGNORE_NFT"
                    logging.error(
                        "[IPS] Gagal menghapus blokir saat IGNORE: %s",
                        result.stderr.strip()
                    )
                    return jsonify({
                        "ok": False,
                        "error": "nftables removal failed; IGNORE remains active"
                    }), 500

            except Exception:
                ips_last_action = "ERROR_IGNORE_EXCEPTION"
                logging.exception("[IPS] Exception saat memproses IGNORE.")
                return jsonify({
                    "ok": False,
                    "error": "nftables exception; IGNORE remains active"
                }), 500

        ips_last_action = (
            "IGNORED_UNBLOCKED" if block_status else "IGNORED"
        )

    logging.warning(
        "[IPS] IGNORE diterapkan untuk case=%s IP=%s. "
        "Auto-block dinonaktifkan sampai IDS NORMAL.",
        case_id, src_ip
    )

    return jsonify({
        "ok": True,
        "action": ips_last_action,
        "attacker_ip": src_ip,
        "ignore_active": True,
        "ids_state": current_state
    }), 200


# ─── ENDPOINT /status ────────────────────────────────────
@app.route("/status", methods=["GET"])
def status():
    with _counters_lock:
        total  = _counters["total"]
        normal = _counters["normal"]
        dos    = _counters["dos"]
    with ids_lock:
        ids_state = IDS_STATE
        atk_ctr   = IDS_ATTACK_COUNTER
        rec_ctr   = IDS_RECOVERY_COUNTER

    with ips_counter_lock:
        ips_atk_ctr = IPS_ATTACK_COUNTER
        ips_triggered = IPS_BLOCK_TRIGGERED
        ips_ignored = IPS_IGNORE_ACTIVE
        ips_ignore_case = IPS_IGNORE_CASE_ID

    return jsonify({
        "server"           : "running",
        "ml_ready"         : ML_READY,
        "current_label"    : current_label,
        "total_data"       : total,
        "normal"           : normal,
        "dos"              : dos,
        "queue_pending"    : write_queue.qsize(),
        "ids_state"        : ids_state,
        "attack_counter"   : atk_ctr,
        "recovery_counter" : rec_ctr,
        "ips_attack_counter": ips_atk_ctr,
        "ips_attack_threshold": IPS_ATTACK_THRESHOLD,
        "ips_block_triggered": ips_triggered,
        "ips_ignore_active": ips_ignored,
        "ips_ignore_case_id": ips_ignore_case,
        "ips_last_action": ips_last_action,
        "csv_file"         : CSV_FILE,
    }), 200

# ─── MAIN ────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"{CY}{'='*60}{R}")
    print(f"{BO}  🛡️  EDGE IDS SERVER v7.0 — RF + XGBoost + State Machine + Resource{R}")
    print(f"  Port            : {PORT}")
    print(f"  Log file        : {CSV_FILE}")
    print(f"  ML Status       : {f'{GR}READY{R}' if ML_READY else f'{RE}NOT READY{R}'}")
    print(f"  Attack threshold: {ATTACK_CONFIRM_THRESHOLD} hit berturut-turut")
    print(f"  Recovery thresh : {RECOVERY_NORMAL_THRESHOLD} normal berturut-turut")
    print(f"  Fitur           : INTERVAL | RTT | JITTER | PACKET RATE")
    print(f"  Resource Monitor: {f'{GR}psutil READY{R}' if PSUTIL_READY else f'{YE}psutil NOT FOUND — pip install psutil{R}'}")
    print(f"{CY}{'='*60}{R}\n")

    try:
        from waitress import serve
        print(f"{GR}[Waitress] Listening 0.0.0.0:{PORT} — 4 threads{R}")
        print(f"{GR}[Waitress] Menunggu data dari ESP32...{R}\n")
        serve(app, host="0.0.0.0", port=PORT, threads=4, _quiet=True)
    except ImportError:
        print(f"{YE}[WARN] pip install waitress — pakai Flask dev server.{R}\n")
        import logging as _log
        _log.getLogger("werkzeug").setLevel(_log.ERROR)
        app.run(host="0.0.0.0", port=PORT, debug=False, use_reloader=False)

