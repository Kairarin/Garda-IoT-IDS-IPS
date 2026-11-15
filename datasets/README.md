# Datasets

| File | Baris | Kolom | Status |
|---|---:|---:|---|
| `dataset_realtime_log.csv` | 114.678 | 22 | **Skema aktif.** Contoh log runtime yang ditulis `edge-server/server.py` (seluruh `label_aktual` = normal). |
| `legacy/dataset_realtime_log_mixed_20261111_231919.csv` | 183.691 | 10 | Arsip eksperimen lama (kolom `latency_ms`, `prediksi_if` / Isolation Forest). Tidak dipakai server saat ini. |
| `legacy/hasil_deteksi.csv` | 17.713 | – | Artefak pipeline lama (`pred_rf`, `pred_iso`). |
| `legacy/ids_alerts.json` | 6.146 record | – | Riwayat alert versi lama (JSON Lines). |

## Skema 22 kolom (`dataset_realtime_log.csv`)

```
timestamp_unix, timestamp_esp, device_id, interval_ms, rtt_ms, jitter_ms, packet_rate,
label_aktual, prediksi_rf, prediksi_xgb, temporary_status, final_status, attack_counter,
recovery_counter, esp32_heap_usage, esp32_cpu_load, pi_cpu, pi_memory, http_success_rate,
communication_loss, timeout_rate, network_health
```

Fitur masukan model: `interval_ms`, `rtt_ms`, `jitter_ms`, `packet_rate`.

> Saat dijalankan, server menulis log baru ke `edge-server/dataset_realtime_log.csv` (di-ignore oleh git).
> Jika file sudah ada dengan header berbeda, server berhenti menulis CSV (`CSV header mismatch`) untuk melindungi data lama.
