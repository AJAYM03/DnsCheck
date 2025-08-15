from flask import Flask, render_template, request, send_file
from scapy.all import sniff, IP, UDP, DNS, DNSQR, DNSRR
import threading
import time
from scapy.all import get_if_list, get_if_addr
for iface in get_if_list():
    try:
        ip = get_if_addr(iface)
    except Exception:
        ip = "No IP"
    print(f"{iface}: {ip}")