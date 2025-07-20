import subprocess
import threading
import time
import os
import sys
from termcolor import colored
from pyfiglet import Figlet
import re

lock = threading.Lock()
stop_threads = False

arp_entries = {}
ping_results = {}
ping_threads = {}

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def beep():
    if os.name == 'nt':
        import winsound
        winsound.Beep(1000, 200)
    else:
        print('\a', end='', flush=True)

def read_arp_table():
    global arp_entries
    if os.name == 'nt':
        # Windows ARP tablosu
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            lines = result.stdout.strip().split('\n')
        except Exception:
            lines = []
        new_entries = {}
        for line in lines:
            if 'dynamic' in line or 'static' in line:
                parts = line.split()
                if len(parts) >= 3:
                    ip = parts[0]
                    mac = parts[1].replace('-', ':').lower()
                    state = parts[2]
                    if ip.count('.') == 3:
                        new_entries[ip] = {'mac': mac, 'state': state}
        with lock:
            arp_entries = new_entries
    else:
        # Linux ARP tablosu
        try:
            result = subprocess.run(['ip', 'neigh'], capture_output=True, text=True)
            output = result.stdout.strip()
            lines = output.split('\n')
        except Exception:
            lines = []
        new_entries = {}
        for line in lines:
            parts = line.split()
            if len(parts) < 4:
                continue
            ip = parts[0]
            if 'lladdr' in parts:
                lladdr_index = parts.index('lladdr')
                mac = parts[lladdr_index + 1]
            else:
                mac = ''
            state = parts[-1] if len(parts) > 4 else ''
            if ip.count('.') == 3 and mac and state != 'FAILED':
                new_entries[ip] = {'mac': mac, 'state': state}
        with lock:
            arp_entries = new_entries

def continuous_arp_update():
    while not stop_threads:
        read_arp_table()
        time.sleep(5)

def ping_ip_forever(ip):
    global ping_results
    while not stop_threads:
        param = '-n' if os.name == 'nt' else '-c'
        ping_cmd = ['ping', param, '1', ip]
        try:
            proc = subprocess.run(ping_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            alive = proc.returncode == 0
            ping_time = None
            output = proc.stdout.lower()

            if alive:
                match_win = re.search(r'time[=<]\s*(\d+)\s*ms', output)
                match_linux = re.search(r'time=([\d\.]+)\s*ms', output)
                if match_win:
                    ping_time = float(match_win.group(1))
                elif match_linux:
                    ping_time = float(match_linux.group(1))
            with lock:
                ping_results[ip] = (alive, ping_time)
        except Exception:
            with lock:
                ping_results[ip] = (False, None)
        time.sleep(1)

def guess_os(mac):
    prefixes = {
        '70:28:8b': 'Samsung',
        '00:50:f1': 'Modem',
        'ba:af:e0': 'Unknown',
        'e6:6c:bf': 'Unknown',
    }
    prefix = mac.lower()[0:8]
    return prefixes.get(prefix, 'Unknown')

def print_header():
    clear_screen()
    f = Figlet(font='slant')
    ascii_art = f.renderText('MAC Tracker')
    print(colored(ascii_art, 'cyan'))
    print(colored("© by Ahmet Efe Uslu\n", 'yellow'))
    print(colored("💻 MAC Tracking & Network Device Analyzer\n", 'green'))
    print(colored("Starting scan... Modem IPs are shown.\n", 'magenta'))
    header_line = f"{'IP Address':<18} {'MAC Address':<18} {'State':<10} {'Ping':<20} OS Guess"
    print(colored(header_line, 'cyan'))
    print(colored("-" * len(header_line), 'cyan'))

def main():
    global stop_threads

    print_header()

    # İLK ARP TABLOSUNU GÜNCELLE
    read_arp_table()

    # ARP güncelleme thread’i başlat
    arp_thread = threading.Thread(target=continuous_arp_update)
    arp_thread.daemon = True
    arp_thread.start()

    # İLK PİNG THREADLERİNİ BAŞLAT
    with lock:
        for ip in arp_entries.keys():
            t = threading.Thread(target=ping_ip_forever, args=(ip,))
            t.daemon = True
            t.start()
            ping_threads[ip] = t

    modem_mac = None
    with lock:
        for ip, data in arp_entries.items():
            if ip.endswith('.1'):
                modem_mac = data['mac']
                break

    previous_display_lines = 0

    try:
        while True:
            with lock:
                current_ips = set(arp_entries.keys())

                # Yeni IP’ler için ping thread başlat
                for ip in current_ips:
                    if ip not in ping_threads:
                        t = threading.Thread(target=ping_ip_forever, args=(ip,))
                        t.daemon = True
                        t.start()
                        ping_threads[ip] = t

                # Kaldırılan IP’leri temizle
                for ip in list(ping_threads.keys()):
                    if ip not in current_ips:
                        ping_results.pop(ip, None)
                        ping_threads.pop(ip, None)

                display_lines = []
                mitm_detected = False
                seen = set()

                for ip in sorted(current_ips):
                    data = arp_entries[ip]
                    mac = data['mac']
                    state = data['state']
                    ping_state, ping_time = ping_results.get(ip, (False, None))

                    ping_str = (colored(f"REACHABLE ({ping_time:.1f}ms)", 'green') if ping_state and ping_time is not None 
                                else colored("REACHABLE", 'green') if ping_state 
                                else colored("UNREACHABLE", 'red'))
                    os_guess = colored(guess_os(mac), 'yellow')
                    state_colored = colored(state, 'cyan')

                    # MITM kontrolü
                    if modem_mac and mac.lower() == modem_mac.lower() and not ip.endswith('.1'):
                        mitm_detected = True
                        mitm_warning = colored("WARNING: Possible MITM attack detected! Same MAC as modem found on different IP.", "red", attrs=["bold"])
                        beep()
                    else:
                        mitm_warning = None

                    line = f"{ip:<18} {mac:<18} {state_colored:<10} {ping_str:<20} {os_guess}"
                    if (ip, mac) not in seen:
                        display_lines.append(line)
                        seen.add((ip, mac))

                # Önceki çıktı satırları kadar yukarı çıkar
                if previous_display_lines > 0:
                    sys.stdout.write(f"\033[{previous_display_lines}F")

                for line in display_lines:
                    sys.stdout.write("\r" + line.ljust(100) + "\n")

                if mitm_detected:
                    print(mitm_warning)

                previous_display_lines = len(display_lines) + (1 if mitm_detected else 0)

            sys.stdout.flush()
            time.sleep(5)

    except KeyboardInterrupt:
        stop_threads = True
        print("\nDo you want to save the scan results to a file? (y/n): ", end='')
        choice = input().strip().lower()
        if choice == 'y':
            filename = f"mac_scan_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                with lock:
                    for ip in sorted(arp_entries.keys()):
                        data = arp_entries[ip]
                        mac = data['mac']
                        state = data['state']
                        ping_state, ping_time = ping_results.get(ip, (False, None))
                        ping_str = 'REACHABLE' if ping_state else 'UNREACHABLE'
                        os_guess = guess_os(mac)
                        f.write(f"{ip:<18} {mac:<18} {state:<10} {ping_str:<10} {os_guess}\n")
            print(colored(f"Results saved to {filename}", 'green'))

if __name__ == "__main__":
    main()