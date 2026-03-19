#!/bin/bash
# Tenda AC15 Authenticated Recording Helper
# This script is intended to be run while QEMU is in record mode.

TARGET_IP="127.0.0.1"

echo "[*] Sending Login Request (admin/admin)..."
# Tenda AC15 login usually uses 'password' field in goform/login
# Using -s for silent, -d for POST data
curl -s -d "password=admin" "http://$TARGET_IP/goform/login" > /dev/null

echo "[*] Waiting for session establishment..."
sleep 2

echo "[*] Sending Target Request (The one we will fuzz)..."
# We'll hit a known sensitive endpoint to serve as the start of fuzzing
curl -s "http://$TARGET_IP/goform/getSysTime" > /dev/null

echo "[*] Waiting for application to process..."
sleep 5

echo "[*] Sending dummy requests to extend trace buffer..."
curl -s "http://$TARGET_IP/goform/getSysTime?dummy=1" > /dev/null
curl -s "http://$TARGET_IP/goform/getSysTime?dummy=2" > /dev/null
sleep 2

echo "[+] Requests sent successfully."
