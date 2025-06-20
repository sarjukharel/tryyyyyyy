
import pyshark
from collections import defaultdict

def detect_anomalies(pcap_file, threshold=50):
    print(f"[+] Analyzing {pcap_file}")
    syn_count = defaultdict(int)

    cap = pyshark.FileCapture(pcap_file, display_filter='tcp.flags.syn==1 && tcp.flags.ack==0')
    for pkt in cap:
        try:
            src = pkt.ip.src
            syn_count[src] += 1
        except AttributeError:
            continue

    print("\n[+] SYN Count:")
    for ip, count in syn_count.items():
        alert = f"{ip}: {count} SYNs"
        if count > threshold:
            alert += " 🚨 ALERT"
        print(alert)

if __name__ == '__main__':
    file = input("Enter .pcap file path: ")
    detect_anomalies(file)
