import threading
from flask import Flask, render_template, jsonify, Response
from flask_socketio import SocketIO
from sniffer import DNSMonitor, packet_queue
import logging
import network_utils
import config
import models
import sys
import socket
import time
import os
import json

# --- Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
app.config['DEBUG'] = False

# CRITICAL FIX: Switch to 'threading' mode. 
# This removes the need for Eventlet and uses standard, stable Python threads.
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins="*")

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

def background_emitter():
    """Reads the queue, SAVES TO DB, and pushes data to the browser"""
    while True:
        try:
            if not packet_queue.empty():
                data = packet_queue.get()
                
                # 1. Save to Database (Persistence)
                models.save_log_entry(data)
                
                # 2. Push to WebSocket (Real-time)
                socketio.emit('new_log', data)
            
            # Use standard time.sleep (since we are in threading mode)
            time.sleep(0.1)
        except Exception as e:
            print(f"[ERROR] Emitter loop failed: {e}")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/history')
def get_history():
    """API Endpoint to fetch past logs"""
    logs = models.get_recent_logs(limit=200)
    return jsonify(logs)

@app.route('/api/stats')
def get_stats():
    """API Endpoint to fetch real-time dynamic stats for the dashboard."""
    # 1. Deployment Zone (Get active interface)
    interface = config.get_active_interface()
    
    # 2. Threat Intel (Count IPs in the dynamic blacklist)
    blacklist_count = 0
    if os.path.exists("dynamic_blacklist.json"):
        try:
            with open("dynamic_blacklist.json", "r") as f:
                blacklist_count = len(json.load(f))
        except Exception:
            pass
            
    # 3. Heuristic Engine (Count how many total alerts we've blocked recently)
    logs = models.get_recent_logs(limit=1000)
    alerts_blocked = sum(1 for log in logs if log.get('status') == 'alert')

    return jsonify({
        "zone": interface,
        "threat_intel": blacklist_count,
        "alerts_blocked": alerts_blocked
    })

@app.route('/api/export')
def export_csv():
    """API Endpoint to export logs as a CSV file for compliance auditing."""
    logs = models.get_recent_logs(limit=10000) # Fetch up to 10,000 recent logs
    
    def generate():
        # Yield the CSV Headers
        yield "ID,Timestamp,Domain,Detected_IP,Status,Message\n"
        # Yield each row
        for log in logs:
            # Wrap message in quotes to prevent commas in the message from breaking the CSV
            yield f"{log.get('id', '')},{log.get('timestamp', '')},{log.get('domain', '')},{log.get('ip', '')},{log.get('status', '')},\"{log.get('message', '')}\"\n"
            
    return Response(
        generate(), 
        mimetype='text/csv', 
        headers={'Content-Disposition': 'attachment; filename=nids_audit_log.csv'}
    )

def get_local_ip():
    """Finds the local IP address for the dashboard URL"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

if __name__ == '__main__':
    print("\n" + "="*50)
    print("DNS SPOOF DETECTOR - ENTERPRISE SOC NODE")
    print("="*50 + "\n")

    # Initialize Database
    print("[-] Initializing Database...")
    try:
        models.init_db()
    except Exception as e:
        print(f"[CRITICAL] Database failed to initialize: {e}")
        sys.exit(1)

    # 1. Interactive Interface Selection
    try:
        selected_iface, selected_ip = network_utils.select_interface_interactive()
        
        # 2. Update Global Config
        config.set_manual_interface(selected_iface)
        
        # Determine Binding Host
        if selected_ip.startswith("127."):
            bind_host = "127.0.0.1"
            local_url = "http://127.0.0.1:5001"
            lan_url = "N/A (Loopback Mode)"
        else:
            bind_host = "0.0.0.0"
            local_url = "http://127.0.0.1:5001"
            lan_url = f"http://{get_local_ip()}:5001"

        print(f"\n[+] Server Configured:")
        print(f"    Interface: {selected_iface}")
        print(f"    IP Address: {selected_ip}")
        print(f"    Binding Host: {bind_host}")
        print(f"    Local Dashboard: {local_url}")
        print(f"    Network Dashboard: {lan_url}")
        print("-" * 50)

    except KeyboardInterrupt:
        print("\n[!] Aborted by user.")
        sys.exit(0)

    print("[-] Starting Background Sniffer...")
    # The sniffer is already a threading.Thread, so it works natively
    monitor = DNSMonitor()
    monitor.start()
    
    print("[-] Starting Web Server...")
    socketio.start_background_task(background_emitter)
    
    try:
        # allow_unsafe_werkzeug required for threading mode in some Flask versions
        socketio.run(app, host=bind_host, port=5001, debug=False, allow_unsafe_werkzeug=True)
    except OSError as e:
        print(f"\n[ERROR] Port 5001 is busy! Error: {e}")
        monitor.stop()
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] Stopping Sniffer...")
        monitor.stop()
        sys.exit(0)