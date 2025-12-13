import threading
import json
import time
import dns.resolver
from queue import Queue
from scapy.all import sniff, DNS, DNSQR, DNSRR, IP, get_if_addr
import config
import notifier

# Global Queue
packet_queue = Queue()

class DNSMonitor(threading.Thread):
    def __init__(self):
        super().__init__()
        self.stop_event = threading.Event()
        self.daemon = True
        self.interface = config.get_active_interface()
        self.trusted_records = self.load_trusted_domains()
        self.my_ip = self.get_own_ip()
        
        # NIDS TRACKING: Key is NOW (transaction_id, client_ip)
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

    def query_public_dns(self, domain):
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8']
            answers = resolver.resolve(domain, 'A', lifetime=2)
            return {answer.to_text() for answer in answers}, answers.rrset.ttl
        except Exception:
            return set(), 0

    def analyze_packet(self, packet):
        # 1. Must be IPv4 DNS
        if not packet.haslayer(DNS) or not packet.haslayer(IP):
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # --- LOGIC 1: TRACK REQUESTS (FROM STUDENTS) ---
        if packet[DNS].qr == 0: # Query
            try:
                qid = packet[DNS].id
                qname = packet[DNSQR].qname.decode().strip('.')
                
                # NIDS LOGIC: Map the Request ID to the SPECIFIC STUDENT (Source IP)
                # We track that "Student X asked for Google with ID 1234"
                self.pending_requests[(qid, src_ip)] = (qname, time.time())
            except:
                pass
            return 

        # --- LOGIC 2: ANALYZE RESPONSES (TO STUDENTS) ---
        if packet[DNS].qr == 1: # Response
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
                if rr.type == 1:  # Type A
                    response_ips.append(rr.rdata)
                    response_ttl = rr.ttl

            if not response_ips:
                return

            status = "safe"
            alert_msg = "Safe Response"
            is_suspicious = False

            # --- DETECTOR A: TRANSACTION ID (CONTEXT AWARE) ---
            # The response is sent TO the student (dst_ip).
            # Did that student (dst_ip) ask for this ID?
            request_key = (tx_id, dst_ip)

            if request_key in self.pending_requests:
                # Valid match: Student asked for this.
                del self.pending_requests[request_key]
            else:
                # UNMATCHED: Either we missed the request (packet loss) or it's an attack.
                # In a college NIDS, we flagging this is crucial for blind spoof detection.
                status = "alert"
                alert_msg = f"⛔ UNSOLICITED for {dst_ip}! TXID {tx_id} not requested."
                is_suspicious = True

            # --- DETECTOR B: IP SPOOF CHECK ---
            detected_ip = response_ips[0]
            
            domain_info = self.trusted_records.get(domain_query)
            expected_ips = set()
            expected_ttl = 300 

            if domain_info:
                expected_ips = set(domain_info.get("ips", []))
                expected_ttl = domain_info.get("ttl", 300)
            elif config.CHECK_GOOGLE_DNS:
                expected_ips, live_ttl = self.query_public_dns(domain_query)
                if live_ttl > 0: expected_ttl = live_ttl

            if expected_ips:
                if detected_ip not in expected_ips:
                    status = "alert"
                    alert_msg = f"❌ SPOOF TARGETING {dst_ip}! {domain_query} -> {detected_ip}"
                    is_suspicious = True
                else:
                    # --- DETECTOR C: TTL ANOMALY ---
                    if not is_suspicious:
                        if response_ttl < 5 or response_ttl > (expected_ttl * 2):
                            status = "alert"
                            alert_msg = f"⚠️ TTL ANOMALY for {dst_ip}! Got {response_ttl}s"
                            is_suspicious = True
                        else:
                            status = "ok"
                            # Log safe packets only for "Warning" or purely specific traffic to save DB space?
                            # For now, we log everything to show activity on the dashboard.
                            alert_msg = f"Verified: {detected_ip} (Student: {dst_ip})"
            else:
                if not is_suspicious:
                    status = "warning"
                    alert_msg = f"Unknown Domain: {detected_ip}"

            if is_suspicious:
                telegram_msg = (
                    f"🚨 *NETWORK THREAT DETECTED!* 🚨\n\n"
                    f"🎯 *Victim:* `{dst_ip}`\n"
                    f"🌐 *Domain:* `{domain_query}`\n"
                    f"📝 *Alert:* `{alert_msg}`\n"
                    f"💀 *Fake IP:* `{detected_ip}`"
                )
                notifier.send_telegram_message(telegram_msg)

            log_entry = {
                "timestamp": time.strftime("%H:%M:%S"),
                "domain": domain_query,
                "ip": detected_ip,
                "status": status,
                "message": alert_msg
            }
            packet_queue.put(log_entry)
            print(f"[{status.upper()}] {dst_ip} : {alert_msg}")

            # Cleanup
            if len(self.pending_requests) > 5000: # Increased buffer for college scale
                self.pending_requests.clear()

    def run(self):
        # We assume the interface is in Promiscuous mode or we are on the Gateway
        print(f"[*] NIDS Sniffer started on {self.interface}...")
        sniff(
            iface=self.interface,
            filter=f"udp port {config.DNS_PORT}", 
            prn=self.analyze_packet,
            store=0,
            stop_filter=lambda x: self.stop_event.is_set()
        )

    def stop(self):
        self.stop_event.set()