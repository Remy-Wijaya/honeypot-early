import socket
import threading
import time
import sys
import queue
import csv
import os
from collections import defaultdict

# ============================================================
# KONFIGURASI
# ============================================================
BIND_IP              = "0.0.0.0"
MONITORED_TCP        = [21, 22, 23, 80, 443, 3306, 8080]
MONITORED_UDP        = [53, 161, 1900]
LOG_FILE_TXT         = "honeypot_alerts.log"
LOG_FILE_CSV         = "honeypot_alerts.csv"

CSV_FIELDS = ["timestamp", "label", "ip", "proto", "port",
              "uniq_ports", "tcp_req", "udp_req"]

DDOS_TCP_THRESHOLD   = 100
DDOS_UDP_THRESHOLD   = 100
BRUTEFORCE_THRESHOLD = 5
WINDOW_SECONDS       = 30

# --- Port Scan Detection ---
# Nmap default scan menyebar koneksi ke banyak port berbeda.
# Threshold = 3 agar terdeteksi meski port 22 tidak di-listen honeypot.
# PORT_SCAN_WINDOW lebih panjang (120s) karena Nmap bisa sangat lambat.
PORTSCAN_THRESHOLD   = 3      # unique port berbeda dalam PORT_SCAN_WINDOW
PORT_SCAN_WINDOW     = 120    # detik — window khusus akumulasi port scan

# --- Rate-based early flood detection ---
FLOOD_EARLY_REQ  = 10
FLOOD_EARLY_SEC  = 2.0

# ============================================================
# WARNA ANSI (terminal real-time)
# ============================================================
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    GREEN   = "\033[92m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"
    DIM     = "\033[2m"

LABEL_COLOR = {
    "DDOS TCP FLOOD" : C.RED,
    "DDOS UDP FLOOD" : C.RED,
    "PORT SCAN"      : C.YELLOW,
    "BRUTE FORCE"    : C.MAGENTA,
    "NORMAL"         : C.GREEN,
}

# ============================================================
# PRINT QUEUE — satu thread yang menulis ke stdout & file
# Solusi utama agar display TIDAK lambat:
#   - Listener thread hanya push ke queue (non-blocking, ~microsecond)
#   - Printer thread flush langsung setiap baris
# ============================================================
print_queue = queue.Queue()

def printer_thread():
    # --- Buka .log (plain text, line-buffered) ---
    log_fh = open(LOG_FILE_TXT, "a", encoding="utf-8", buffering=1)

    # --- Buka .csv (tulis header hanya jika file baru / kosong) ---
    csv_is_new = not os.path.exists(LOG_FILE_CSV) or os.path.getsize(LOG_FILE_CSV) == 0
    csv_fh  = open(LOG_FILE_CSV, "a", encoding="utf-8", newline="")
    writer  = csv.DictWriter(csv_fh, fieldnames=CSV_FIELDS)
    if csv_is_new:
        writer.writeheader()
        csv_fh.flush()

    while True:
        item = print_queue.get()
        if item is None:
            break
        ts, ip, proto, port, label, uniq_ports, tcp_req, udp_req = item

        color = LABEL_COLOR.get(label, C.WHITE)

        # --- Terminal (berwarna) ---
        line = (
            f"{C.DIM}[{ts}]{C.RESET} "
            f"{C.BOLD}{color}{label:<16}{C.RESET} "
            f"| {C.CYAN}IP{C.RESET}={C.WHITE}{ip:<15}{C.RESET} "
            f"| {C.CYAN}{proto:<3}{C.RESET} "
            f"port={C.WHITE}{port:<5}{C.RESET} "
            f"| ports={uniq_ports:<3} "
            f"tcp={C.RED}{tcp_req:<5}{C.RESET} "
            f"udp={C.YELLOW}{udp_req}{C.RESET}"
        )
        print(line, flush=True)

        # --- Plain text log ---
        log_fh.write(
            f"[{ts}] {label:<16} | IP={ip:<15} | {proto:<3} port={port:<5} "
            f"| ports={uniq_ports:<3} tcp={tcp_req:<5} udp={udp_req}\n"
        )

        # --- CSV log (flush tiap baris agar langsung tersimpan) ---
        writer.writerow({
            "timestamp" : ts,
            "label"     : label,
            "ip"        : ip,
            "proto"     : proto,
            "port"      : port,
            "uniq_ports": uniq_ports,
            "tcp_req"   : tcp_req,
            "udp_req"   : udp_req,
        })
        csv_fh.flush()

    log_fh.close()
    csv_fh.close()

# ============================================================
# STATE
# ============================================================
stats_lock = threading.Lock()
ip_stats   = defaultdict(lambda: {
    # Window utama (DDoS / BruteForce)
    "ports"            : set(),
    "tcp_req"          : 0,
    "udp_req"          : 0,
    "window_start"     : time.time(),
    "first_req"        : time.time(),
    # Window khusus Port Scan (lebih panjang, tidak ikut reset window utama)
    "scan_ports"       : set(),   # akumulasi unique port dalam PORT_SCAN_WINDOW
    "scan_window_start": time.time(),
})

# ============================================================
# KLASIFIKASI
# ============================================================
def get_label(s: dict, now: float) -> str:
    tcp        = s["tcp_req"]
    udp        = s["udp_req"]
    ports      = len(s["ports"])
    scan_ports = len(s["scan_ports"])   # unique port dalam PORT_SCAN_WINDOW

    # --- Early rate detection (flood ramp-up) ---
    elapsed      = max(now - s["first_req"], 0.001)
    tcp_rate     = tcp / elapsed
    is_fast_flood = (tcp >= FLOOD_EARLY_REQ and elapsed <= FLOOD_EARLY_SEC)

    if tcp >= DDOS_TCP_THRESHOLD or is_fast_flood:
        return "DDOS TCP FLOOD"
    if udp >= DDOS_UDP_THRESHOLD:
        return "DDOS UDP FLOOD"
    # Port Scan: pakai scan_ports (window panjang) agar Nmap lambat tetap terdeteksi
    if scan_ports >= PORTSCAN_THRESHOLD:
        return "PORT SCAN"
    # Brute Force: laju lambat, sedikit port target
    if tcp >= BRUTEFORCE_THRESHOLD and ports < 3 and tcp_rate < 5.0:
        return "BRUTE FORCE"
    return "NORMAL"

# ============================================================
# HANDLER — hanya update stats + push ke queue, TIDAK print langsung
# ============================================================
def handle_traffic(ip: str, port: int, proto: str) -> None:
    now = time.time()

    with stats_lock:
        s = ip_stats[ip]

        # Reset window utama
        if now - s["window_start"] > WINDOW_SECONDS:
            s["tcp_req"]      = 0
            s["udp_req"]      = 0
            s["ports"]        = set()
            s["window_start"] = now
            s["first_req"]    = now

        # Reset window port scan (terpisah, lebih panjang)
        if now - s["scan_window_start"] > PORT_SCAN_WINDOW:
            s["scan_ports"]        = set()
            s["scan_window_start"] = now

        if proto == "TCP":
            s["tcp_req"] += 1
        else:
            s["udp_req"] += 1
        s["ports"].add(port)
        s["scan_ports"].add(port)   # selalu akumulasi ke scan window

        label      = get_label(s, now)
        uniq_ports = len(s["ports"])
        tcp_req    = s["tcp_req"]
        udp_req    = s["udp_req"]

    ts = time.strftime("%H:%M:%S")

    # Non-blocking push — listener tidak pernah nunggu printer
    print_queue.put_nowait((ts, ip, proto, port, label, uniq_ports, tcp_req, udp_req))

# ============================================================
# LISTENERS
# ============================================================
def start_tcp_listener(port: int, ready: threading.Event, fail: list) -> None:
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((BIND_IP, port))
        srv.listen(500)
        ready.set()          # bind berhasil — beri tahu main thread
        while True:
            try:
                client, addr = srv.accept()
                client.close()
                handle_traffic(addr[0], port, "TCP")
            except OSError:
                break
    except OSError as e:
        fail.append(str(e))
        ready.set()          # tetap set agar main thread tidak nunggu selamanya

def start_udp_listener(port: int, ready: threading.Event, fail: list) -> None:
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((BIND_IP, port))
        ready.set()
        while True:
            try:
                _, addr = srv.recvfrom(4096)
                handle_traffic(addr[0], port, "UDP")
            except OSError:
                break
    except OSError as e:
        fail.append(str(e))
        ready.set()

# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    sys.stdout.reconfigure(line_buffering=True)

    pt = threading.Thread(target=printer_thread, daemon=False)
    pt.start()

    header = (
        "\033[1m\033[96m"
        "╔══════════════════════════════════════════════════════════╗\n"
        "║          PyHoneypot — Real-time Threat Monitor           ║\n"
        "╚══════════════════════════════════════════════════════════╝"
        "\033[0m"
    )
    print(header, flush=True)
    print(f"  TCP ports  : {MONITORED_TCP}", flush=True)
    print(f"  UDP ports  : {MONITORED_UDP}", flush=True)
    print(f"  Log TXT    : {LOG_FILE_TXT}", flush=True)
    print(f"  Log CSV    : {LOG_FILE_CSV}", flush=True)
    print(f"  Window     : {WINDOW_SECONDS}s  (setiap paket langsung tampil)", flush=True)
    print(f"\033[2m{'─'*62}\033[0m", flush=True)
    print(f"\033[2m  [time]   LABEL            | IP              | proto port  | stats\033[0m", flush=True)
    print(f"\033[2m{'─'*62}\033[0m", flush=True)

    failed_ports = []

    for p in MONITORED_TCP:
        ev, err = threading.Event(), []
        t = threading.Thread(target=start_tcp_listener, args=(p, ev, err), daemon=True)
        t.start()
        ev.wait(timeout=2)          # tunggu sampai bind selesai (max 2 detik)
        if err:
            print(f"  \033[91m✗\033[0m TCP port {p:5}  ← GAGAL BIND: {err[0]}", flush=True)
            failed_ports.append(("TCP", p, err[0]))
        else:
            print(f"  \033[92m✓\033[0m TCP listener port {p}", flush=True)

    for p in MONITORED_UDP:
        ev, err = threading.Event(), []
        t = threading.Thread(target=start_udp_listener, args=(p, ev, err), daemon=True)
        t.start()
        ev.wait(timeout=2)
        if err:
            print(f"  \033[91m✗\033[0m UDP port {p:5}  ← GAGAL BIND: {err[0]}", flush=True)
            failed_ports.append(("UDP", p, err[0]))
        else:
            print(f"  \033[92m✓\033[0m UDP listener port {p}", flush=True)

    if failed_ports:
        print(f"\n\033[93m[!] {len(failed_ports)} port gagal di-bind (sudah dipakai service lain atau butuh sudo).\033[0m", flush=True)
        print(f"\033[93m    Port yang gagal TIDAK akan mendeteksi serangan!\033[0m", flush=True)
        print(f"\033[93m    Jalankan dengan: sudo python3 honeypot.py\033[0m", flush=True)

    print(f"\n\033[2m{'─'*62}\033[0m", flush=True)
    print(f"  \033[1mMenunggu koneksi... (Ctrl+C untuk berhenti)\033[0m\n", flush=True)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n\033[93m[*] Menghentikan honeypot...\033[0m", flush=True)
        print_queue.put(None)
        pt.join(timeout=2)
        print(f"\033[92m[*] Honeypot dimatikan.\033[0m", flush=True)
        print(f"\033[92m    TXT : {LOG_FILE_TXT}\033[0m", flush=True)
        print(f"\033[92m    CSV : {LOG_FILE_CSV}\033[0m")
