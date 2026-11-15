// ============================================================
//  GARDA-IoT · konfigurasi firmware ESP32
//  1. Salin file ini menjadi config.h (di folder yang sama).
//  2. Isi kredensial Wi-Fi dan alamat jaringan lab Anda.
//  config.h sudah masuk .gitignore sehingga tidak ikut ter-push.
// ============================================================
#pragma once

// --- Wi-Fi (2.4 GHz) ---
#define WIFI_SSID      "YOUR_WIFI_SSID"
#define WIFI_PASSWORD  "YOUR_WIFI_PASSWORD"

// --- Edge server (IP Raspberry Pi 5 yang menjalankan server.py) ---
#define EDGE_SERVER_IP "192.168.X.X"

// --- Identitas perangkat (muncul di dashboard, CSV, dan alert) ---
#define GARDA_DEVICE_ID "ESP32-IDS-01"

// --- IP statis ESP32 (pisahkan dengan koma) ---
// Nilai ESP32_STATIC_IP harus sama dengan GARDA_ESP32_IP di garda.env.
#define ESP32_STATIC_IP  192,168,X,X
#define ESP32_GATEWAY    192,168,X,1
#define ESP32_SUBNET     255,255,255,0
#define ESP32_DNS1       8,8,8,8
#define ESP32_DNS2       1,1,1,1
