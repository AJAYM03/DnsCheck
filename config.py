import logging

# --- Global State ---
# This variable will be set by app.py at startup
SNIFFER_INTERFACE = None 

# --- Constants ---
TRUSTED_DOMAINS_FILE = "trusted_domains.json"
DNS_PORT = 53
CHECK_GOOGLE_DNS = True

# --- Alerts Configuration ---
ENABLE_TELEGRAM = True 
# Your Token (Pre-filled)
TELEGRAM_BOT_TOKEN = "8306274058:AAH0wLqna6yhiT2KTt3PZOWCvxbNaa8AtOg"
# !!! PASTE YOUR NUMERIC CHAT ID BELOW !!!
TELEGRAM_CHAT_ID = "1258000126" 

def set_manual_interface(iface_name):
    """Called by app.py to set the user-selected interface"""
    global SNIFFER_INTERFACE
    SNIFFER_INTERFACE = iface_name

def get_active_interface():
    """Called by sniffer.py to get the configuration"""
    if SNIFFER_INTERFACE:
        return SNIFFER_INTERFACE
    return "lo"