INDRA FINAL 1.1
================

Language: Python 3
Targets: Termux/Android and Linux; some commands are platform-specific.

FILES
- INDRA.py: complete single-file toolkit. Existing tools and new OSINT categories are integrated here.
- install.sh: optional Termux dependency installer.

RUN
  python INDRA.py

TERMUX SETUP
  pkg update
  pkg install python iproute2 iputils traceroute
  python -m pip install dnspython scapy
  python INDRA.py

Optional Python packages:
- dnspython: expanded DNS records and MX lookups.
- scapy: PCAP inspection and supported live capture.

OSINT CATEGORIES
- OSINT / SITES: domain profile, passive certificate-transparency subdomain lookup, IP profile, RDAP registration data.
- OSINT / PEOPLE: public username URL checks, search-query link builder, local email syntax/domain checks. No mailbox probing.
- OSINT / PROFILES: public page metadata inspection.

Notes
- Username URL checks are indicative and can produce false positives/negatives due to site blocking or generic pages.
- Public search results do not prove identity. Use only lawful public-source research; do not use this tool to harass, expose private information, or access private accounts.
- Live packet capture depends on Android/kernel support and permissions; root alone does not guarantee it.
- Reports are written locally to ./indra_reports/.
- This version has no auto-updater. Future OS/Python changes may require compatibility fixes.
