from scapy.all import send, IP, UDP, DNS, DNSQR, DNSRR
import random
import time

victim_ip = "127.0.0.1"
dns_server_ip = "8.8.8.8"

def load_legit_domains(file_path="expected.txt"):
    legit_domains = {}
    with open(file_path, "r") as f:
        for line in f:
            if ':' in line:
                domain, ips = line.strip().split(":", 1)
                ip_list = [ip.strip() for ip in ips.split(",") if ip.strip()]
                if ip_list:
                    legit_domains[domain.strip()] = random.choice(ip_list)  # Pick one IP
    return legit_domains

def random_ip():
    return f"{random.randint(10,250)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def send_dns_response(domain, ip, spoofed=False):
    pkt = (
        IP(dst=victim_ip, src=dns_server_ip) /
        UDP(dport=random.randint(1024, 65535), sport=53) /
        DNS(
            id=random.randint(1, 65535),
            qr=1,
            qd=DNSQR(qname=domain),
            an=DNSRR(rrname=domain, ttl=60, rdata=ip)
        )
    )
    send(pkt, verbose=0)
    print(f"[{'FAKE' if spoofed else 'LEGIT'}] {domain} → {ip}")

def simulate():
    legit_domains = load_legit_domains()
    if not legit_domains:
        print("No domains found in expected.txt.")
        return

    while True:
        domain = random.choice(list(legit_domains.keys()))
        if random.choice([True, False]):
            send_dns_response(domain + ".", legit_domains[domain], spoofed=False)
        else:
            send_dns_response(domain + ".", random_ip(), spoofed=True)
        time.sleep(1)

if __name__ == "__main__":
    simulate()
