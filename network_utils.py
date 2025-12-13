import socket
from scapy.all import get_if_list, get_if_addr, conf

def get_valid_interfaces():
    """
    Returns a list of tuples: (name, ip, description)
    """
    interfaces = []
    
    # 1. Add Scapy detected interfaces
    if_list = get_if_list()
    for iface in if_list:
        try:
            ip = get_if_addr(iface)
            # Filter out empty or zero addresses
            if ip and ip != "0.0.0.0":
                # On Windows, 'conf.iface' often holds the friendly name logic
                desc = iface
                if hasattr(conf, 'manuf'):
                    # Try to get a better description if possible
                    pass 
                interfaces.append((iface, ip, "Network Adapter"))
        except Exception:
            continue
            
    # 2. Explicitly add Loopback if not found (Common on Windows)
    # Windows loopback is often named specific things in Scapy
    loopback_found = any(ip.startswith("127.") for _, ip, _ in interfaces)
    if not loopback_found:
        # Try to find the standard loopback name
        lo_name = conf.loopback_name
        interfaces.append((lo_name, "127.0.0.1", "Loopback (Software)"))
        
    return interfaces

def auto_detect_interface():
    """
    Returns the 'best' non-loopback interface with an IP.
    """
    interfaces = get_valid_interfaces()
    
    # Prefer non-local IPs (192.x, 10.x, 172.x)
    for name, ip, desc in interfaces:
        if not ip.startswith("127."):
            return name, ip
            
    # Fallback to loopback
    return conf.loopback_name, "127.0.0.1"

def select_interface_interactive():
    """
    CLI Menu for selecting an interface.
    Returns (interface_name, interface_ip)
    """
    print("Available Network Interfaces:")
    interfaces = get_valid_interfaces()
    
    # Display List
    print(f"   {'No.':<4} {'IP Address':<16} {'Interface Name/GUID'}")
    print("-" * 60)
    
    for idx, (name, ip, desc) in enumerate(interfaces):
        # Truncate long GUIDs for display
        display_name = (name[:35] + '..') if len(name) > 35 else name
        print(f"   {idx+1:<4} {ip:<16} {display_name}")
        
    print("-" * 60)
    print("A. Auto-Detect (Best IPv4)")
    print("L. Force Loopback (127.0.0.1)")
    
    while True:
        choice = input("\nSelect Interface [A]: ").strip().upper()
        
        if not choice or choice == 'A':
            name, ip = auto_detect_interface()
            print(f"[*] Auto-selected: {ip}")
            return name, ip
            
        if choice == 'L':
            return conf.loopback_name, "127.0.0.1"
            
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(interfaces):
                return interfaces[idx][0], interfaces[idx][1]
            else:
                print("Invalid number.")
        except ValueError:
            print("Invalid input.")