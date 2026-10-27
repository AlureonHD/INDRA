#!/data/data/com.termux/files/usr/bin/bash
set -eu
pkg update
pkg install -y python iproute2 iputils traceroute
python -m pip install --upgrade pip
python -m pip install dnspython scapy
printf '\nINDRA dependencies installed. Run: python INDRA.py\n'
