from flask import Flask, render_template, request, send_file
from scapy.all import sniff, IP, UDP, DNS, DNSQR, DNSRR
import threading
import time
import os
import dns.resolver 

app = Flask(__name__)
LOG_FILE = "spoof_log.txt"
EXPECTED_IPS_FILE = "expected.txt"
log_data = []
expected_dns_records = {}

def load_expected_dns_records(filename):
    records = {}
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                try:
                    domain, ips_str = line.split(':', 1)
                    ips = [ip.strip() for ip in ips_str.split(',')]
                    records[domain.strip()] = ips
                except ValueError:
                    print(f"Skipping malformed line in {filename}: {line}")
        print(f"Loaded {len(records)} expected DNS records from {filename}")
    except FileNotFoundError:
        print(f"Error: Expected IPs file '{filename}' not found.")
    except Exception as e:
        print(f"Error loading expected DNS records: {e}")
    return records

def log_message(msg):
    timestamp = time.strftime("[%Y-%m-%d %H:%M:%S] ", time.localtime())
    full_msg = timestamp + msg
    log_data.append(full_msg)
    with open(LOG_FILE, "a") as f:
        f.write(full_msg + "\n")
    print(full_msg)

def query_public_dns(domain):
    """
    Query public DNS resolver (Google 8.8.8.8) for A records of the domain.
    Returns a set of IP strings or empty set on failure.
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8']
        answers = resolver.resolve(domain, 'A', lifetime=2)
        return set([answer.to_text() for answer in answers])
    except Exception as e:
        log_message(f"[ERROR] Public DNS query failed for {domain}: {e}")
        return set()

def detect_spoof(packet):
    print("[PACKET RECEIVED]")
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 1 and packet.haslayer(DNSRR):
        if packet.haslayer(DNSQR):
            domain_query = packet[DNSQR].qname.decode().strip('.')
        else:
            domain_query = "unknown"

        # Get static expected IPs from file
        expected_ips_static = set(expected_dns_records.get(domain_query, []))

        # Query live DNS if no static expected IPs found
        expected_ips_live = set()
        if not expected_ips_static:
            expected_ips_live = query_public_dns(domain_query)

        # Combine static and live expected IPs
        combined_expected_ips = expected_ips_static.union(expected_ips_live)

        for i in range(packet[DNS].ancount):
            answer = packet[DNS].an[i]
            try:
                response_ip = str(answer.rdata)
            except Exception as e:
                response_ip = f"unreadable_rdata ({e})"

            if answer.type == 1:  # A record
                if combined_expected_ips:
                    if response_ip not in combined_expected_ips:
                        log_message(f"[ALERT] {domain_query} -> {response_ip} (Expected: {sorted(combined_expected_ips)})")
                    else:
                        log_message(f"[OK] {domain_query} -> {response_ip}")
                else:
                    log_message(f"[INFO] No expected IPs found for {domain_query}. Got: {response_ip}")
            else:
                log_message(f"[INFO] Received {domain_query} -> {response_ip} (Type: {answer.type})")

    elif packet.haslayer(DNS) and packet.getlayer(DNS).qr == 1:
        log_message("[INFO] Received a DNS response without an answer.")

@app.route('/')
def home():
    show_alerts = request.args.get('alerts', 'false').lower() == 'true'
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, "w").close()

    with open(LOG_FILE, "r") as f:
        lines = f.readlines()
    if show_alerts:
        lines = filter(lambda line: "[ALERT]" in line, lines)

    return render_template("index.html", log=''.join(lines), alerts=show_alerts)
from flask import jsonify, render_template_string

@app.route('/logs')
def get_logs():
    show_alerts = request.args.get('alerts', 'false').lower() == 'true'
    
    if not os.path.exists(LOG_FILE):
        return "", 204  

    with open(LOG_FILE, "r") as f:
        lines = f.readlines()

    if show_alerts:
        lines = [line for line in lines if "[ALERT]" in line]

    # Convert each line to a styled <div class="log-line">
    log_html_lines = []
    for line in lines:
        css_class = "log-line"
        if "[ALERT]" in line:
            css_class += " alert"
        elif "[OK]" in line:
            css_class += " ok"
        elif "[INFO]" in line:
            css_class += " info"
        elif "[ERROR]" in line:
            css_class += " error"
        log_html_lines.append(f'<div class="{css_class}">{line.strip()}</div>')

    return "\n".join(log_html_lines)

@app.route('/download')
def download_log():
    return send_file(LOG_FILE, as_attachment=True)

def start_sniffing():
    sniff(filter="udp port 53", iface="\\Device\\NPF_{A49181D7-8804-45B8-8D43-4DEC76C125A3}", prn=detect_spoof, store=0)

if __name__ == "__main__":
    open(LOG_FILE, "a+").close()
    expected_dns_records = load_expected_dns_records(EXPECTED_IPS_FILE)
    if not expected_dns_records:
        print("WARNING: No expected DNS records loaded. The detector will only log INFO messages.")

    threading.Thread(target=start_sniffing, daemon=True).start()
    app.run(debug=False)
