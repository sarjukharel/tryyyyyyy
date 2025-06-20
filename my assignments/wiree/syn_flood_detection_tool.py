import pyshark
from collections import defaultdict
from datetime import datetime
import os


def detect_syn_flood(pcap_path, threshold=100):
    print(f"[*] Analyzing: {pcap_path}\n")
    syn_counter = defaultdict(int)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = f"syn_flood_alerts_{timestamp}.txt"

    try:
        cap = pyshark.FileCapture(pcap_path, display_filter="tcp.flags.syn == 1 && tcp.flags.ack == 0")

        for pkt in cap:
            try:
                ip = pkt.ip.src
                syn_counter[ip] += 1
            except AttributeError:
                continue  # non-IP packet

        with open(log_file, 'w') as log:
            log.write("=== SYN Flood Detection Report ===\n")
            for ip, count in syn_counter.items():
                line = f"{ip}: {count} SYNs"
                if count > threshold:
                    line += " 🚨 ALERT: Potential SYN Flood"
                print(line)
                log.write(line + '\n')

        print(f"\n[✔] Report saved to {log_file}")

    except Exception as e:
        print(f"[!] Error during analysis: {e}")


if __name__ == "__main__":
    print("=== SYN Flood Detection Tool ===")
    path = input("Enter path to .pcap file: ").strip()
    detect_syn_flood(path)
