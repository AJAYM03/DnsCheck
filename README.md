# DNS Spoofing Detection & Alert System

A **lightweight, real-time system** to protect public Wi-Fi networks from DNS spoofing attacks, developed during my internship at **Cochin International Airport Ltd. (CIAL)**. Built with **Python, Scapy, Flask, and Socket.IO**, it detects spoofed DNS responses, highlights threats visually, triggers alert sounds, and maintains downloadable logs.

## Features

* Live DNS packet sniffing and monitoring
* Spoof detection based on IP mismatches and trusted domain file
* Integration with Google Public DNS for dynamic verification
* Web-based dashboard with **red-highlighted alerts** and audio notifications
* Downloadable logs for analysis

## Why This Project

Public Wi-Fi networks are vulnerable to DNS spoofing, which can redirect users to malicious sites. Our goal was to create a **cost-effective, easy-to-use tool** for the network security team to detect and respond to threats in real time.

## How It Works

1. Captures DNS responses in real time
2. Compares IPs against trusted mappings (local + Google DNS)
3. Flags suspicious responses with visual and audio alerts
4. Maintains logs for review

## Tech Stack

* **Python** for packet sniffing & backend
* **Scapy** for DNS packet analysis
* **Flask** for web dashboard
* **Socket.IO** for real-time alerts
