import threading
import ipaddress
import json
import time
import os
import dns.resolver
from queue import Queue
from scapy.all import sniff, DNS, DNSQR, DNSRR, IP, get_if_addr
import config
import notifier

# Global Queue for streaming to the web dashboard
packet_queue = Queue()

class DNSMonitor(threading.Thread):
    def __init__(self):
        super().__init__()
        self.stop_event = threading.Event()
        self.daemon = True
        self.interface = config.get_active_interface()
        self.trusted_records = self.load_trusted_domains()
        self.my_ip = self.get_own_ip()
        
        # Insider Threat Blacklist Configuration
        self.blacklist_file = "dynamic_blacklist.json"
        self.blacklisted_ips = self.load_blacklist()
        
        # NIDS TRACKING: Key is (transaction_id, client_ip)
        # Value is (domain, timestamp)
        self.pending_requests = {} 

    def get_own_ip(self):
        try:
            return get_if_addr(self.interface)
        except:
            return "127.0.0.1"

    def load_trusted_domains(self):
        try:
            with open(config.TRUSTED_DOMAINS_FILE, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            print(f"[ERROR] Could not load {config.TRUSTED_DOMAINS_FILE}.")
            return {}

    def load_blacklist(self):
        """Loads the dynamically updated list of known insider threats."""
        if not os.path.exists(self.blacklist_file):
            with open(self.blacklist_file, 'w') as f:
                json.dump([], f)
            return set()
        
        try:
            with open(self.blacklist_file, 'r') as f:
                return set(json.load(f))
        except json.JSONDecodeError:
            return set()

    def add_to_blacklist(self, malicious_ip):
        """Writes newly discovered malicious local IPs to the persistent file."""
        if malicious_ip not in self.blacklisted_ips:
            self.blacklisted_ips.add(malicious_ip)
            try:
                with open(self.blacklist_file, 'w') as f:
                    json.dump(list(self.blacklisted_ips), f, indent=4)
                print(f"\n[+] THREAT INTEL: Added {malicious_ip} to {self.blacklist_file}")
            except Exception as e:
                print(f"\n[ERROR] Failed to update blacklist: {e}")

    def query_public_dns(self, domain):
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8']
            answers = resolver.resolve(domain, 'A', lifetime=2)
            return {answer.to_text() for answer in answers}, answers.rrset.ttl
        except Exception:
            return set(), 0

    def trigger_alert(self, target_ip, domain, fake_ip, alert_msg, status):
        """Handles the professional formatting and dispatching of alerts."""
        telegram_msg = (
            f"CRITICAL: NIDS Security Alert\n"
            f"----------------------------------------\n"
            f"Timestamp    : {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Target Host  : {target_ip}\n"
            f"Query Domain : {domain}\n"
            f"Suspicious IP: {fake_ip}\n"
            f"Violation    : {alert_msg}\n"
            f"----------------------------------------\n"
            f"Action Req   : Immediate isolation of Target Host recommended."
        )
        notifier.send_telegram_message(telegram_msg)

        log_entry = {
            "timestamp": time.strftime("%H:%M:%S"),
            "domain": domain,
            "ip": fake_ip,
            "status": status,
            "message": alert_msg
        }
        packet_queue.put(log_entry)

        log_prefix = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [NIDS] [{status.upper():<7}]"
        print(f"{log_prefix} SRC:{target_ip:<15} | QUERY:{domain:<25} | MSG:{alert_msg}")

    def analyze_packet(self, packet):
        if not packet.haslayer(DNS) or not packet.haslayer(IP):
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # --- LOGIC LAYER 1: TRACK OUTBOUND REQUESTS ---
        if packet[DNS].qr == 0: 
            try:
                qid = packet[DNS].id
                qname = packet[DNSQR].qname.decode().strip('.')
                
                # DETECTOR 1: DNS Tunneling / Exfiltration (Length Anomaly)
                if len(qname) > 75:
                    alert_msg = "DATA EXFILTRATION RISK! Suspiciously long DNS query length."
                    self.trigger_alert(src_ip, qname, "N/A", alert_msg, "alert")

                self.pending_requests[(qid, src_ip)] = (qname, time.time())
            except:
                pass
            return 

        # --- LOGIC LAYER 2: ANALYZE INBOUND RESPONSES ---
        if packet[DNS].qr == 1: 
            if not packet.haslayer(DNSRR):
                return

            try:
                domain_query = packet[DNSQR].qname.decode().strip('.')
                tx_id = packet[DNS].id
            except:
                return

            response_ips = []
            response_ttl = 0
            
            for i in range(packet[DNS].ancount):
                rr = packet[DNS].an[i]
                if rr.type == 1:  
                    response_ips.append(rr.rdata)
                    response_ttl = rr.ttl

            if not response_ips:
                return

            detected_ip = response_ips[0]
            violations = []
            is_suspicious = False

            # --- DETECTOR 2: DYNAMIC BLACKLIST MATCH ---
            if detected_ip in self.blacklisted_ips:
                violations.append(f"KNOWN THREAT: {detected_ip} is Blacklisted")
                is_suspicious = True

            # --- DETECTOR 3: UNREQUESTED PACKET INJECTION ---
            request_key = (tx_id, dst_ip)
            if request_key in self.pending_requests:
                del self.pending_requests[request_key]
            else:
                violations.append(f"UNSOLICITED RESPONSE: TXID {tx_id} not requested")
                is_suspicious = True

            # --- DETECTOR 4: INSIDER THREAT (LOCAL IP HEURISTIC) ---
            try:
                is_private_ip = ipaddress.ip_address(detected_ip).is_private
            except ValueError:
                is_private_ip = False

            if is_private_ip:
                violations.append(f"INSIDER THREAT: Redirect to LOCAL IP {detected_ip}")
                is_suspicious = True
                # AUTO-LEARNING: Add the attacker's server to the persistent blacklist
                self.add_to_blacklist(detected_ip)
            
            # --- DETECTOR 5: TTL ANOMALY ---
            if response_ttl != 0 and (response_ttl < 5 or response_ttl > 3600):
                violations.append(f"TTL ANOMALY: ({response_ttl}s)")
                is_suspicious = True

            # --- DISPATCH LOGS AND ALERTS ---
            if is_suspicious:
                status = "alert"
                # Combine all violations into one detailed message for the SIEM
                alert_msg = " | ".join(violations)
                self.trigger_alert(dst_ip, domain_query, detected_ip, alert_msg, status)
            else:
                status = "ok"
                alert_msg = "Verified standard traffic"
                log_entry = {
                    "timestamp": time.strftime("%H:%M:%S"),
                    "domain": domain_query,
                    "ip": detected_ip,
                    "status": status,
                    "message": alert_msg
                }
                packet_queue.put(log_entry)
                log_prefix = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [NIDS] [{status.upper():<7}]"
                print(f"{log_prefix} SRC:{dst_ip:<15} | QUERY:{domain_query:<25} | MSG:{alert_msg}")

            if len(self.pending_requests) > 5000:
                self.pending_requests.clear()

    def run(self):
        print(f"[*] NIDS Engine Initialized.")
        print(f"[*] Threat Intel: Loaded {len(self.blacklisted_ips)} known malicious IPs.")
        print(f"[*] Binding to interface: {self.interface}")
        print(f"[*] Awaiting network traffic on UDP port {config.DNS_PORT}...")
        sniff(
            iface=self.interface,
            filter=f"udp port {config.DNS_PORT}", 
            prn=self.analyze_packet,
            store=0,
            stop_filter=lambda x: self.stop_event.is_set()
        )

    def stop(self):
        print("\n[!] Shutting down NIDS background sniffer...")
        self.stop_event.set()