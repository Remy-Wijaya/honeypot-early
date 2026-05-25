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

# Batasan Durasi Penelitian (6 Menit = 360 Detik)
RUN_DURATION_SECONDS = 360  

CSV_FIELDS = ["timestamp", "label", "ip", "proto", "port",
              "uniq_ports", "tcp_req", "udp_req"]

DDOS_TCP_THRESHOLD   = 100
DDOS_UDP_THRESHOLD   = 100
BRUTEFORCE_THRESHOLD = 5
WINDOW_SECONDS       = 30

# --- Port Scan Detection ---
PORTSCAN_THRESHOLD   = 3      
PORT_SCAN_WINDOW     = 120    

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
# PRINT QUEUE â€” Menulis ke stdout & file
# ============================================================
print_queue = queue.Queue()

def printer_thread():
    log_fh = open(LOG_FILE_TXT, "a", encoding="utf-8", buffering=1)
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

        # Terminal
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

        # Plain text log
        log_fh.write(
            f"[{ts}] {label:<16} | IP={ip:<15} | {proto:<3} port={port:<5} "
            f"| ports={uniq_ports:<3} tcp={tcp_req:<5} udp={udp_req}\n"
        )

        # CSV log
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
    "ports"            : set(),
    "tcp_req"          : 0,
    "udp_req"          : 0,
    "window_start"     : time.time(),
    "first_req"        : time.time(),
    "scan_ports"       : set(),   
    "scan_window_start": time.time(),
    "has_been_bruteforce": False  
})

# ============================================================
# PERBAIKAN LOGIKA KLASIFIKASI (Anti-Lompat)
# ============================================================
def get_label(s: dict, now: float) -> str:
    tcp        = s["tcp_req"]
    udp        = s["udp_req"]
    ports      = len(s["ports"])
    scan_ports = len(s["scan_ports"])   

    # 1. Deteksi Port Scan Terlebih Dahulu
    if scan_ports >= PORTSCAN_THRESHOLD and ports >= 3:
        return "PORT SCAN"

    # 2. Kunci Status Brute Force
    if (tcp >= BRUTEFORCE_THRESHOLD and ports < 3) or s["has_been_bruteforce"]:
        if tcp < BRUTEFORCE_THRESHOLD and s["has_been_bruteforce"]:
            return "BRUTE FORCE"
        
        s["has_been_bruteforce"] = True
        
        if tcp >= DDOS_TCP_THRESHOLD:
            return "DDOS TCP FLOOD"
            
        return "BRUTE FORCE"

    # 3. Deteksi DDoS Murni
    if tcp >= DDOS_TCP_THRESHOLD:
        return "DDOS TCP FLOOD"
    if udp >= DDOS_UDP_THRESHOLD:
        return "DDOS UDP FLOOD"

    return "NORMAL"

# ============================================================
# HANDLER
# ============================================================
def handle_traffic(ip: str, port: int, proto: str) -> None:
    now = time.time()

    with stats_lock:
        s = ip_stats[ip]

        # Reset window utama (30 detik)
        if now - s["window_start"] > WINDOW_SECONDS:
            s["tcp_req"]      = 0
            s["udp_req"]      = 0
            s["ports"]        = set()
            s["window_start"] = now
            s["first_req"]    = now

        # Reset window port scan (120 detik)
        if now - s["scan_window_start"] > PORT_SCAN_WINDOW:
            s["scan_ports"]        = set()
            s["scan_window_start"] = now

        if proto == "TCP":
            s["tcp_req"] += 1
        else:
            s["udp_req"] += 1
        s["ports"].add(port)
        s["scan_ports"].add(port)   

        label      = get_label(s, now)
        uniq_ports = len(s["ports"])
        tcp_req    = s["tcp_req"]
        udp_req    = s["udp_req"]

    ts = time.strftime("%H:%M:%S")
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
        ready.set()          
        while True:
            try:
                client, addr = srv.accept()
                client.close()
                handle_traffic(addr[0], port, "TCP")
            except OSError:
                break
    except OSError as e:
        fail.append(str(e))
        ready.set()          

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
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":
    sys.stdout.reconfigure(line_buffering=True)

    pt = threading.Thread(target=printer_thread, daemon=False)
    pt.start()

    print("============================================================", flush=True)
    print("           PyHoneypot -- Real-time Threat Monitor           ", flush=True)
    print("============================================================", flush=True)
    print(f"  TCP ports  : {MONITORED_TCP}", flush=True)
    print(f"  UDP ports  : {MONITORED_UDP}", flush=True)
    print(f"  Log TXT    : {LOG_FILE_TXT}", flush=True)
    print(f"  Log CSV    : {LOG_FILE_CSV}", flush=True)
    print(f"  Durasi Run : {RUN_DURATION_SECONDS} detik (6 Menit)", flush=True)
    print("------------------------------------------------------------", flush=True)
    print("  [time]   LABEL            | IP              | proto port  | stats", flush=True)
    print("------------------------------------------------------------", flush=True)

    failed_ports = []

    for p in MONITORED_TCP:
        ev, err = threading.Event(), []
        t = threading.Thread(target=start_tcp_listener, args=(p, ev, err), daemon=True)
        t.start()
        ev.wait(timeout=2)          
        if err:
            failed_ports.append(("TCP", p, err[0]))
        else:
            print(f"  \033[92mâœ“\033[0m TCP listener port {p}", flush=True)

    for p in MONITORED_UDP:
        ev, err = threading.Event(), []
        t = threading.Thread(target=start_udp_listener, args=(p, ev, err), daemon=True)
        t.start()
        ev.wait(timeout=2)
        if err:
            failed_ports.append(("UDP", p, err[0]))
        else:
            print(f"  \033[92mâœ“\033[0m UDP listener port {p}", flush=True)

    print(f"\n  Honeypot aktif! Menghitung mundur 6 menit penelitian...\n", flush=True)

    start_time = time.time()
    try:
        while True:
            elapsed_run = time.time() - start_time
            if elapsed_run >= RUN_DURATION_SECONDS:
                print(f"\n[+] Waktu penelitian (6 menit) telah terpenuhi otomatis.", flush=True)
                break
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n[*] Dihentikan manual oleh user.", flush=True)

    print(f"[*] Menghentikan honeypot dan menyimpan log...", flush=True)
    print_queue.put(None)
    pt.join(timeout=2)
    print(f"[*] Selesai! Log aman di: {LOG_FILE_CSV}")
