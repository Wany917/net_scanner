import scapy.all as scapy
import time, threading
from colorama import init,Fore
init(autoreset=True)

GREEN = Fore.GREEN
RED = Fore.RED
YELLOW = Fore.YELLOW
NEUTRAL = Fore.RESET
CYAN = Fore.CYAN

def catch_packets(pkt_count, filename):
    try:
        pkts = scapy.sniff(count=pkt_count)
        scapy.wrpcap(filename, pkts)
        print(f"{Fore.LIGHTYELLOW_EX}[!]{Fore.LIGHTYELLOW_EX} Packets captured and saved to {filename}")
    except Exception as e:
        print(f"{RED}[-]{RED} Error: {e}")


def start_packets_in_thread(pkt_count, filename):
    pkt_thread = threading.Thread(target=catch_packets, args=(pkt_count, filename))
    pkt_thread.start()
    return pkt_thread


def extract_ips_from_file(filename):
    # Pour eviter les doublons sur les ips j'fais "tableau associatif"
    ips =  set()
    try:
        pkts = scapy.rdpcap(filename)
        for pkt in pkts:
            if 'IP' in pkt:
                source_ip = pkt['IP'].src
                dest_ip = pkt['IP'].dst

                ips.add((source_ip, dest_ip))
    except Exception as e:
        print(f"{RED}[-]{RED} Error: {e}")
    return ips

def display_ip_list(ips):
    for src, dst in ips:
        print(f"{GREEN}[+] {CYAN}{src} {NEUTRAL} -> {Fore.MAGENTA}{dst}")

def main():
    catch_packets(15, 'captures.pcap')
    ips = extract_ips_from_file('captures.pcap')
    display_ip_list(ips)


if __name__ == '__main__':
    print(Fore.GREEN+'[v] STARTING . . .')
    time.sleep(5)
    main()