import threading
import requests
import time
import config

# Prevent alert fatigue (Max 1 alert every 5 seconds)
last_alert_time = 0
ALERT_COOLDOWN = 5 

def send_telegram_message(text):
    """Sends a message to the configured Telegram Chat"""
    global last_alert_time
    
    if not config.ENABLE_TELEGRAM:
        return

    # Check Cooldown to prevent flooding your phone
    if time.time() - last_alert_time < ALERT_COOLDOWN:
        return

    last_alert_time = time.time()

    def _worker():
        token = config.TELEGRAM_BOT_TOKEN
        chat_id = config.TELEGRAM_CHAT_ID
        
        # Validation
        if "PASTE_YOUR" in str(chat_id) or not token:
            print("[!] Telegram Alert Failed: Chat ID or Token not set in config.py")
            return

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        data = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "Markdown"
        }
        
        try:
            requests.post(url, data=data, timeout=5)
        except Exception as e:
            print(f"[!] Telegram Notification Failed: {e}")

    # Run in a separate thread to avoid blocking the sniffer
    threading.Thread(target=_worker, daemon=True).start()