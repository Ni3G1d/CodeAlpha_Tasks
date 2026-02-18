from scapy.all import sniff, get_if_addr
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR
from datetime import datetime
from colorama import Fore, Style, init
import socket

init(autoreset=True)

LOCAL_IP = get_if_addr("Ethernet")  # change to Wi-Fi if needed

log_file = open("packet_log.txt", "a")

common_ports = {
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    110: "POP3",
    143: "IMAP"
}

def get_service(port):
    return common_ports.get(port, "Unknown")

def format_output(data):
    print(data)
    log_file.write(data + "\n")

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]

        # Only capture traffic involving local machine
        if ip_layer.src != LOCAL_IP and ip_layer.dst != LOCAL_IP:
            return

        timestamp = datetime.now().strftime("%H:%M:%S")

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        protocol = "OTHER"
        service = "-"
        src_port = "-"
        dst_port = "-"
        dns_query = "-"

        if packet.haslayer(TCP):
            protocol = "TCP"
            tcp_layer = packet[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            service = get_service(dst_port)

        elif packet.haslayer(UDP):
            protocol = "UDP"
            udp_layer = packet[UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            service = get_service(dst_port)

        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            dns_query = packet[DNSQR].qname.decode()

        output = (
            f"{Fore.CYAN}[{timestamp}] "
            f"{Fore.YELLOW}{protocol:<5} "
            f"{Fore.GREEN}{src_ip}:{src_port} "
            f"{Fore.MAGENTA}-> "
            f"{Fore.RED}{dst_ip}:{dst_port} "
            f"{Fore.WHITE}| Service: {service} "
            f"| DNS: {dns_query}"
        )

        format_output(output)

print(Fore.BLUE + "\nMini Wireshark Started...")
print(Fore.BLUE + f"Monitoring Local IP: {LOCAL_IP}")
print(Fore.BLUE + "Press Ctrl+C to stop\n")

sniff(filter="ip", prn=packet_callback, store=False)
