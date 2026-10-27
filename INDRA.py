#!/usr/bin/env python3
"""INDRA — modular defensive security and diagnostics toolkit.
Python 3.10+. Works best on Termux/Android and Linux; some features are platform-specific.
Use only on systems and domains you own or are explicitly authorized to assess.
"""
from __future__ import annotations
import os, sys, ssl, json, csv, time, socket, hashlib, secrets, string, ipaddress
import platform, stat, shutil, subprocess, urllib.request, urllib.error, urllib.parse
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---- Red-on-black terminal theme ----
RED = '\033[91m'; DARK_RED = '\033[31m'; BRIGHT = '\033[1m'; DIM = '\033[2m'
RESET = '\033[0m'; BG_BLACK = '\033[40m'; WHITE = '\033[97m'
APP = 'INDRA'; VERSION = 'FINAL 1.1'
REPORT_DIR = Path('indra_reports')


def paint(text, color=RED, bold=False):
    return f"{BG_BLACK}{color}{BRIGHT if bold else ''}{text}{RESET}{BG_BLACK}{RED}"

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(BG_BLACK + RED, end='')

def banner():
    logo = r"""██╗███╗   ██╗██████╗ ██████╗  █████╗
██║████╗  ██║██╔══██╗██╔══██╗██╔══██╗
██║██╔██╗ ██║██║  ██║██████╔╝███████║
██║██║╚██╗██║██║  ██║██╔══██╗██╔══██╗
██║██║ ╚████║██████╔╝██║  ██║██║  ██║
╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝"""
    print(paint(logo, RED, True))
    print(paint(f'        {APP} // {VERSION}', RED, True))
    print(paint('        DEFENSIVE SECURITY & DIAGNOSTICS', DARK_RED))
    print(paint('═' * 64, DARK_RED))

def heading(title):
    clear(); banner(); print(paint(f'\n[ {title.upper()} ]\n', RED, True))

def pause():
    try: input(paint('\n[ ENTER ] Return to menu...', DARK_RED))
    except (EOFError, KeyboardInterrupt): pass

def ask(prompt):
    return input(paint(f'[INDRA] {prompt}: ', RED, True)).strip()

def valid_host(value):
    value=value.strip()
    if not value or any(c in value for c in '/\\ \t\r\n') or '://' in value:
        raise ValueError('Enter a hostname or IP address only (no URL scheme or path).')
    return value

def valid_url(value):
    p=urllib.parse.urlparse(value)
    if p.scheme not in ('http','https') or not p.hostname:
        raise ValueError('Enter a complete http:// or https:// URL.')
    return p

def report(name, data):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    path=REPORT_DIR/f'{name}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    with path.open('w',encoding='utf-8') as f: json.dump(data,f,indent=2,ensure_ascii=False,default=str)
    print(paint(f'[REPORT] Saved: {path}', DARK_RED))
    return path

def optional_import(module):
    try:
        import importlib
        return importlib.import_module(module)
    except ImportError:
        return None

def run_command(args, timeout=15):
    p=subprocess.run(args,capture_output=True,text=True,timeout=timeout,errors='replace')
    return {'command':args,'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr}

# ============================ NETWORK ============================
def local_network():
    heading('NETWORK / Local Network Overview')
    data={'hostname':socket.gethostname(),'platform':platform.platform(),'interfaces':{},'command_outputs':{},'uid':getattr(os,'getuid',lambda:None)()}
    try:
        data['addresses']=sorted({x[4][0] for x in socket.getaddrinfo(socket.gethostname(),None)})
    except OSError: data['addresses']=[]
    for cmd in (['ip','-brief','address'],['ip','route']):
        if shutil.which(cmd[0]):
            res=run_command(cmd,8); data['command_outputs']['ip_address' if 'address' in cmd else 'routes']=res['stdout'].strip() or res['stderr'].strip()
    try:
        for line in Path('/proc/net/dev').read_text().splitlines()[2:]:
            if ':' in line:
                name,rest=line.split(':',1); vals=rest.split()
                data['interfaces'][name.strip()]={'rx_bytes':int(vals[0]),'tx_bytes':int(vals[8])}
    except OSError: pass
    print(json.dumps(data,indent=2,ensure_ascii=False)); report('network_local',data); pause()

def ping_diagnostics():
    heading('NETWORK / Ping Diagnostics'); host=valid_host(ask('Host or IP'))
    tool=shutil.which('ping')
    if not tool: print('[!] Install ping utility (Termux: pkg install iputils).'); pause(); return
    # A small, fixed number of packets; no stress testing.
    args=[tool,'-c','4','-W','2',host]
    try:
        d=run_command(args,12); print(d['stdout'] or d['stderr']); report('ping',{'host':host,**d})
    except Exception as e: print('[ERROR]',e)
    pause()

def traceroute_diagnostics():
    heading('NETWORK / Traceroute'); host=valid_host(ask('Host or IP'))
    tool=shutil.which('traceroute')
    if tool: args=[tool,'-m','12','-w','1',host]
    else:
        tool=shutil.which('tracepath')
        if tool: args=[tool,host]
        else: print('[!] Install traceroute: pkg install traceroute'); pause(); return
    try:
        d=run_command(args,25); print(d['stdout'] or d['stderr']); report('traceroute',{'host':host,**d})
    except Exception as e: print('[ERROR]',e)
    pause()

def tcp_port_check():
    heading('NETWORK / TCP Port Check'); host=valid_host(ask('Host or IP'))
    raw=ask('Ports separated by commas (e.g. 22,80,443; max 30)')
    try:
        ports=sorted(set(int(x.strip()) for x in raw.split(',')))
        if not ports or len(ports)>30 or any(p<1 or p>65535 for p in ports): raise ValueError
    except ValueError: print('[!] Invalid list; use 1–30 valid ports.'); pause(); return
    print('[i] Use only against systems you own or are authorized to test.')
    rows=[]
    for port in ports:
        state='closed/filtered'; latency=None
        try:
            start=time.monotonic()
            with socket.create_connection((host,port),timeout=1.5): state='open'
            latency=round((time.monotonic()-start)*1000,2)
        except (OSError,TimeoutError): pass
        row={'port':port,'state':state,'latency_ms':latency}; rows.append(row)
        print(f"[{ '+' if state=='open' else '-' }] TCP/{port}: {state}"+(f' ({latency} ms)' if latency is not None else ''))
    report('tcp_ports',{'host':host,'results':rows}); pause()

def dns_lookup():
    heading('NETWORK / DNS Lookup'); host=valid_host(ask('Domain or hostname'))
    data={'host':host,'addresses':[],'records':{}}
    try:
        data['addresses']=sorted({r[4][0] for r in socket.getaddrinfo(host,None)})
        print('[A/AAAA]'); [print(' ',x) for x in data['addresses']]
    except OSError as e: print('[!] System resolver:',e)
    dns=optional_import('dns.resolver')
    if dns:
        for kind in ('A','AAAA','MX','NS','TXT','CAA','SOA','CNAME'):
            try: vals=[str(x) for x in dns.resolve(host,kind,lifetime=3)]
            except Exception: vals=[]
            data['records'][kind]=vals
            if vals:
                print(f'[{kind}]'); [print(' ',x) for x in vals]
    else: print('[i] Optional records need dnspython: python -m pip install dnspython')
    try: data['reverse_dns']={ip:socket.gethostbyaddr(ip)[0] for ip in data['addresses']}
    except OSError: data['reverse_dns']={}
    report('dns_lookup',data); pause()

def packet_analyzer():
    heading('NETWORK / PCAP Packet Analyzer'); scapy=optional_import('scapy.all')
    if not scapy: print('[!] Optional dependency missing: python -m pip install scapy'); pause(); return
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP
    mode=ask('1 = Read PCAP/PCAPNG file, 2 = Live capture (authorized network only)')
    try:
        if mode=='1':
            path=Path(ask('Capture file path').strip('"')).expanduser()
            packets=rdpcap(str(path))[:3000]
        elif mode=='2':
            if not hasattr(os,'geteuid') or os.geteuid()!=0:
                print('[!] Live capture usually requires root.'); pause(); return
            from scapy.all import sniff
            iface=ask('Interface (blank = default)') or None
            packets=sniff(iface=iface,count=100,timeout=15,store=True)
        else: print('[!] Invalid choice.'); pause(); return
        counts={}; rows=[]
        for p in packets:
            proto='OTHER'; src=dst='?'; sport=dport=None
            if IP in p: src,dst=p[IP].src,p[IP].dst
            elif IPv6 in p: src,dst=p[IPv6].src,p[IPv6].dst
            if TCP in p: proto='TCP'; sport,dport=p[TCP].sport,p[TCP].dport
            elif UDP in p: proto='UDP'; sport,dport=p[UDP].sport,p[UDP].dport
            elif ICMP in p: proto='ICMP'
            counts[proto]=counts.get(proto,0)+1
            rows.append({'protocol':proto,'source':src,'destination':dst,'source_port':sport,'destination_port':dport,'length':len(p)})
        print(f'[+] Packets analyzed: {len(rows)} | Protocols: {counts}')
        for r in rows[:80]: print(f"{r['protocol']:5} {r['source']}:{r['source_port'] or '-'} -> {r['destination']}:{r['destination_port'] or '-'} len={r['length']}")
        report('packets',{'count':len(rows),'protocol_counts':counts,'packets':rows})
    except Exception as e: print('[ERROR]',e)
    pause()

# ============================ WEBSITE ============================
def http_security_headers():
    heading('WEBSITE / Security Headers'); url=ask('Full URL (https://...)')
    try:
        valid_url(url); req=urllib.request.Request(url,headers={'User-Agent':'INDRA-Defensive-Audit/1.0'})
        with urllib.request.urlopen(req,timeout=10) as r: status=r.status; headers=dict(r.headers.items()); final=r.geturl()
        checks={'Strict-Transport-Security':'HSTS','Content-Security-Policy':'CSP','X-Content-Type-Options':'MIME sniffing protection','X-Frame-Options':'Clickjacking mitigation','Referrer-Policy':'Referrer policy','Permissions-Policy':'Permissions policy'}
        print(f'[HTTP] {status} | Final URL: {final}')
        for h,label in checks.items(): print(f"[{ 'OK' if h.lower() in {k.lower() for k in headers} else '--' }] {label}: {headers.get(h,'not present')}")
        report('http_headers',{'url':url,'final_url':final,'status':status,'headers':headers,'checks':checks})
    except urllib.error.HTTPError as e: print(f'[HTTP] {e.code} {e.reason}')
    except Exception as e: print('[ERROR]',e)
    pause()

def website_health():
    heading('WEBSITE / Response & Timing'); url=ask('Full URL (https://...)')
    try:
        valid_url(url); req=urllib.request.Request(url,headers={'User-Agent':'INDRA-Defensive-Audit/1.0'})
        start=time.monotonic()
        with urllib.request.urlopen(req,timeout=12) as r:
            sample=r.read(8192); data={'url':url,'final_url':r.geturl(),'status':r.status,'content_type':r.headers.get('Content-Type'),'server_header':r.headers.get('Server'),'sample_bytes':len(sample),'elapsed_ms':round((time.monotonic()-start)*1000,2),'headers':dict(r.headers.items())}
        print(json.dumps(data,indent=2,ensure_ascii=False)); report('website_health',data)
    except urllib.error.HTTPError as e: print(f'[HTTP] {e.code} {e.reason}')
    except Exception as e: print('[ERROR]',e)
    pause()

def tls_inspector():
    heading('WEBSITE / TLS Certificate'); host=valid_host(ask('Hostname (no scheme)'))
    try:
        port=int(ask('Port [443]') or '443')
        if not 1<=port<=65535: raise ValueError('Port out of range')
        ctx=ssl.create_default_context()
        with socket.create_connection((host,port),timeout=7) as raw:
            with ctx.wrap_socket(raw,server_hostname=host) as s: cert=s.getpeercert(); data={'host':host,'port':port,'tls_version':s.version(),'cipher':s.cipher(),'certificate':cert}
        print('[TLS]',data['tls_version'],'| Cipher:',data['cipher']); print('[SUBJECT]',cert.get('subject')); print('[ISSUER]',cert.get('issuer')); print('[VALID FROM]',cert.get('notBefore')); print('[VALID UNTIL]',cert.get('notAfter')); print('[SAN]',cert.get('subjectAltName'))
        report('tls_certificate',data)
    except Exception as e: print('[ERROR]',e)
    pause()

def http_methods():
    heading('WEBSITE / OPTIONS & HEAD'); url=ask('Full URL')
    try: valid_url(url)
    except ValueError as e: print('[!]',e); pause(); return
    rows={}
    for method in ('HEAD','OPTIONS'):
        try:
            req=urllib.request.Request(url,method=method,headers={'User-Agent':'INDRA-Defensive-Audit/1.0'})
            with urllib.request.urlopen(req,timeout=7) as r: rows[method]={'status':r.status,'allow':r.headers.get('Allow'),'headers':dict(r.headers.items())}; print(f"[{method}] HTTP {r.status} Allow={r.headers.get('Allow')}")
        except urllib.error.HTTPError as e: rows[method]={'status':e.code}; print(f'[{method}] HTTP {e.code}')
        except Exception as e: rows[method]={'error':str(e)}; print(f'[{method}] {e}')
    report('http_methods',{'url':url,'results':rows}); pause()

def robots_sitemap():
    heading('WEBSITE / robots.txt & Sitemap'); base=ask('Base URL').rstrip('/')
    try: valid_url(base)
    except ValueError as e: print('[!]',e); pause(); return
    data={}
    for path in ('/robots.txt','/sitemap.xml'):
        try:
            with urllib.request.urlopen(urllib.request.Request(base+path,headers={'User-Agent':'INDRA/1.0'}),timeout=7) as r:
                body=r.read(100_000).decode('utf-8','replace'); data[path]={'status':r.status,'sample':body[:5000]}; print(f'\n[{path}] HTTP {r.status}\n{body[:1600]}')
        except urllib.error.HTTPError as e: data[path]={'status':e.code}; print(f'[{path}] HTTP {e.code}')
        except Exception as e: data[path]={'error':str(e)}; print(f'[{path}] {e}')
    report('robots_sitemap',{'base':base,'results':data}); pause()

def url_redirect_trace():
    heading('WEBSITE / Redirect Destination'); url=ask('Full URL')
    try:
        valid_url(url)
        req=urllib.request.Request(url,method='GET',headers={'User-Agent':'INDRA/1.0'})
        with urllib.request.urlopen(req,timeout=10) as r: data={'requested_url':url,'final_url':r.geturl(),'status':r.status,'redirected':url!=r.geturl(),'headers':dict(r.headers.items())}
        print(json.dumps(data,indent=2,ensure_ascii=False)); report('redirect_check',data)
    except urllib.error.HTTPError as e: print(f'[HTTP] {e.code} {e.reason}')
    except Exception as e: print('[ERROR]',e)
    pause()

# ============================ OSINT ============================
def osint_domain_profile():
    heading('OSINT / Domain Profile'); domain=valid_host(ask('Domain'))
    data={'domain':domain,'timestamp':datetime.now().isoformat(),'addresses':[],'reverse_dns':{},'records':{}}
    try:
        data['addresses']=sorted({x[4][0] for x in socket.getaddrinfo(domain,None)})
        print('[ADDRESSES]'); [print(' ',x) for x in data['addresses']]
    except OSError as e: print('[DNS ERROR]',e)
    for ip in data['addresses']:
        try: data['reverse_dns'][ip]=socket.gethostbyaddr(ip)[0]
        except OSError: pass
    dns=optional_import('dns.resolver')
    if dns:
        for kind in ('MX','NS','TXT','SOA','CAA'):
            try: data['records'][kind]=[str(x) for x in dns.resolve(domain,kind,lifetime=3)]
            except Exception: data['records'][kind]=[]
            if data['records'][kind]: print(f'[{kind}]'); [print(' ',x) for x in data['records'][kind]]
    else: print('[i] Install dnspython for expanded DNS records.')
    report('osint_domain',data); pause()

def passive_subdomains():
    heading('OSINT / Passive Subdomain Discovery'); domain=valid_host(ask('Domain you own or are authorized to assess')).lower()
    try:
        # Certificate Transparency lookup; passive public source, no probing of discovered hosts.
        url='https://crt.sh/?q='+urllib.parse.quote('%.'+domain)+'&output=json'
        req=urllib.request.Request(url,headers={'User-Agent':'INDRA-OSINT/1.0'})
        with urllib.request.urlopen(req,timeout=15) as r: items=json.loads(r.read(2_000_000).decode('utf-8','replace'))
        names=set()
        for item in items:
            for name in item.get('name_value','').splitlines():
                name=name.strip().lower().lstrip('*.')
                if name==domain or name.endswith('.'+domain): names.add(name)
        names=sorted(names); print(f'[+] Public certificate names found: {len(names)}')
        for name in names[:300]: print(' ',name)
        report('osint_subdomains',{'domain':domain,'count':len(names),'subdomains':names})
    except Exception as e: print('[ERROR]',e)
    pause()

def ip_address_profile():
    heading('OSINT / IP Address Profile'); value=ask('IPv4 or IPv6 address')
    try:
        ip=ipaddress.ip_address(value); data={'ip':str(ip),'version':ip.version,'is_private':ip.is_private,'is_global':ip.is_global,'is_loopback':ip.is_loopback,'is_multicast':ip.is_multicast,'is_reserved':ip.is_reserved,'reverse_pointer':ip.reverse_pointer}
        try: data['reverse_dns']=socket.gethostbyaddr(str(ip))[0]
        except OSError: data['reverse_dns']=None
        print(json.dumps(data,indent=2)); report('ip_profile',data)
    except ValueError: print('[!] Invalid IP address.')
    pause()


# ============================ OSINT / PEOPLE ============================
def username_footprint():
    heading('OSINT / PEOPLE / Public Username Footprint')
    username=ask('Public username (no @)').strip()
    if not username or len(username)>64 or any(c.isspace() for c in username):
        print('[!] Enter a single username, up to 64 characters.'); pause(); return
    # Public profile URL checks only. Results are indicative, not proof of identity.
    platforms={
        'GitHub':'https://github.com/{}',
        'GitLab':'https://gitlab.com/{}',
        'Reddit':'https://www.reddit.com/user/{}/',
        'Pinterest':'https://www.pinterest.com/{}/',
        'Twitch':'https://www.twitch.tv/{}',
        'YouTube handle':'https://www.youtube.com/@{}',
        'TikTok':'https://www.tiktok.com/@{}',
        'Instagram':'https://www.instagram.com/{}/',
        'X':'https://x.com/{}',
        'Medium':'https://medium.com/@{}',
        'Codeberg':'https://codeberg.org/{}',
        'Hugging Face':'https://huggingface.co/{}',
    }
    print('[i] Checks public profile pages only; no login, private data, or identity matching.')
    results=[]
    for name,template in platforms.items():
        url=template.format(urllib.parse.quote(username, safe='@'))
        req=urllib.request.Request(url,method='GET',headers={'User-Agent':'INDRA-Public-OSINT/1.0'})
        try:
            with urllib.request.urlopen(req,timeout=5) as r:
                status=r.status; final=r.geturl(); sample=r.read(4096).decode('utf-8','replace').lower()
                # Some sites return a generic page even when a profile does not exist.
                result='HTTP_OK_CHECK_MANUALLY' if status==200 else f'HTTP_{status}'
                if 'page not found' in sample or 'user not found' in sample or 'account not found' in sample:
                    result='LIKELY_NOT_FOUND'
        except urllib.error.HTTPError as e:
            status=e.code; final=url
            result='LIKELY_NOT_FOUND' if status==404 else f'HTTP_{status}'
        except Exception as e:
            status=None; final=url; result='UNAVAILABLE_OR_BLOCKED'
        results.append({'platform':name,'url':final,'status':status,'result':result})
        print(f"[{result:24}] {name:16} {final}")
    print('[!] A matching page does not prove two accounts belong to the same person.')
    report('osint_username_footprint',{'username':username,'results':results,'note':'Indicative public URL checks only; manually verify results.'}); pause()

def people_search_links():
    heading('OSINT / PEOPLE / Search Query Builder')
    term=ask('Public name or username to search')
    if not term: print('[!] Empty query.'); pause(); return
    q=urllib.parse.quote_plus('"'+term+'"')
    queries={
        'Google':f'https://www.google.com/search?q={q}',
        'Bing':f'https://www.bing.com/search?q={q}',
        'DuckDuckGo':f'https://duckduckgo.com/?q={q}',
        'GitHub':f'https://github.com/search?q={urllib.parse.quote_plus(term)}&type=users',
        'Reddit':f'https://www.reddit.com/search/?q={urllib.parse.quote_plus(term)}',
    }
    print('[i] These links search publicly indexed pages; use them lawfully and do not use results to harass or expose private details.')
    for name,url in queries.items(): print(f'[{name}] {url}')
    # Do not save the person's query into a report.
    pause()

def email_domain_check():
    heading('OSINT / PEOPLE / Email Syntax & Domain Check')
    address=ask('Email address to validate locally')
    if len(address)>254 or address.count('@')!=1:
        print('[!] Invalid email syntax.'); pause(); return
    local,domain=address.rsplit('@',1)
    valid=bool(local and len(local)<=64 and domain and '.' in domain and not domain.startswith('.') and not domain.endswith('.') and ' ' not in address)
    print('[SYNTAX]', 'looks plausible' if valid else 'invalid / suspicious syntax')
    if not valid: pause(); return
    print('[DOMAIN]',domain)
    mx=[]
    dns=optional_import('dns.resolver')
    if dns:
        try: mx=[str(x.exchange).rstrip('.') for x in dns.resolve(domain,'MX',lifetime=3)]
        except Exception: mx=[]
        print('[MX]', ', '.join(mx) if mx else 'No MX record found or DNS query failed')
    else:
        try: print('[DNS]', ', '.join(sorted({x[4][0] for x in socket.getaddrinfo(domain,None)})))
        except OSError: print('[DNS] Domain did not resolve using the system resolver.')
    print('[i] This does not confirm that a mailbox exists. No email is sent and no account lookup is attempted.')
    # Avoid saving the full email address in a report.
    pause()

# ============================ OSINT / PUBLIC PROFILES ============================
def public_profile_inspector():
    heading('OSINT / PROFILES / Public Profile Page Inspector')
    url=ask('Public profile URL (https://...)')
    try: valid_url(url)
    except ValueError as e: print('[!]',e); pause(); return
    data={'url':url,'status':None,'final_url':None,'title':None,'description':None,'canonical':None,'open_graph':{},'robots':None,'links_found':0}
    try:
        req=urllib.request.Request(url,headers={'User-Agent':'INDRA-Public-Profile-Inspector/1.0'})
        with urllib.request.urlopen(req,timeout=10) as r:
            raw=r.read(1_000_000).decode('utf-8','replace')
            data['status']=r.status; data['final_url']=r.geturl(); data['content_type']=r.headers.get('Content-Type')
        # Parse only page metadata, not posts, private content, or login-gated data.
        import re
        title=re.search(r'<title[^>]*>(.*?)</title>',raw,re.I|re.S)
        data['title']=re.sub(r'\s+',' ',title.group(1)).strip()[:300] if title else None
        for key,pattern in {
            'description':r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']*)',
            'robots':r'<meta[^>]+name=["\']robots["\'][^>]+content=["\']([^"\']*)',
            'canonical':r'<link[^>]+rel=["\']canonical["\'][^>]+href=["\']([^"\']*)',
        }.items():
            m=re.search(pattern,raw,re.I)
            if m: data[key]=m.group(1)[:500]
        for key in ('og:title','og:description','og:type','og:url','og:image'):
            m=re.search(r'<meta[^>]+property=["\']'+re.escape(key)+r'["\'][^>]+content=["\']([^"\']*)',raw,re.I)
            if m: data['open_graph'][key]=m.group(1)[:500]
        data['links_found']=len(re.findall(r'<a\s',raw,re.I))
        print(json.dumps(data,indent=2,ensure_ascii=False))
        report('osint_public_profile',data)
    except urllib.error.HTTPError as e: print(f'[HTTP] {e.code} {e.reason}')
    except Exception as e: print('[ERROR]',e)
    pause()

def domain_rdap_lookup():
    heading('OSINT / SITES / Domain Registration (RDAP)')
    domain=valid_host(ask('Domain (e.g. example.com)').lower())
    if '.' not in domain or domain.startswith('.') or domain.endswith('.'):
        print('[!] Enter a registered domain name.'); pause(); return
    url='https://rdap.org/domain/'+urllib.parse.quote(domain,safe='.-')
    try:
        req=urllib.request.Request(url,headers={'User-Agent':'INDRA-Public-OSINT/1.0','Accept':'application/rdap+json, application/json'})
        with urllib.request.urlopen(req,timeout=12) as r: payload=json.loads(r.read(500_000).decode('utf-8','replace'))
        events=[{'action':x.get('eventAction'),'date':x.get('eventDate')} for x in payload.get('events',[]) if isinstance(x,dict)]
        nameservers=[x.get('ldhName') for x in payload.get('nameservers',[]) if isinstance(x,dict)]
        data={'domain':domain,'handle':payload.get('handle'),'ldhName':payload.get('ldhName'),'status':payload.get('status',[]),'events':events,'nameservers':nameservers,'entities':[],'source':'Public RDAP'}
        for ent in payload.get('entities',[]):
            if isinstance(ent,dict): data['entities'].append({'roles':ent.get('roles',[]),'handle':ent.get('handle')})
        print(json.dumps(data,indent=2,ensure_ascii=False))
        print('[i] Registration data may be redacted or unavailable; this tool does not bypass privacy protections.')
        report('osint_domain_rdap',data)
    except urllib.error.HTTPError as e: print(f'[RDAP] HTTP {e.code}; registry may not support this lookup.')
    except Exception as e: print('[ERROR]',e)
    pause()

# ============================ SYSTEM ============================
def system_overview():
    heading('SYSTEM / Device Overview')
    data={'python':sys.version,'executable':sys.executable,'platform':platform.platform(),'system':platform.system(),'release':platform.release(),'machine':platform.machine(),'hostname':socket.gethostname(),'cwd':str(Path.cwd()),'uid':getattr(os,'getuid',lambda:None)()}
    print(json.dumps(data,indent=2,ensure_ascii=False)); report('system_overview',data); pause()

def process_overview():
    heading('SYSTEM / Visible Processes'); proc=Path('/proc')
    if not proc.is_dir(): print('[!] /proc is unavailable on this platform.'); pause(); return
    rows=[]
    for p in proc.iterdir():
        if not p.name.isdigit(): continue
        try:
            cmd=p.joinpath('cmdline').read_bytes().replace(b'\0',b' ').decode('utf-8','replace').strip() or p.joinpath('comm').read_text(errors='replace').strip()
            rows.append({'pid':int(p.name),'command':cmd[:220]})
        except OSError: continue
    rows.sort(key=lambda x:x['pid'])
    for r in rows[:100]: print(f"{r['pid']:>7}  {r['command']}")
    print(f'[+] Visible: {len(rows)}; displayed up to 100'); report('processes',{'count':len(rows),'processes':rows}); pause()

def permission_audit():
    heading('SYSTEM / File Permission Audit'); path=Path(ask('File or directory path').strip('"')).expanduser()
    if not path.exists(): print('[!] Path does not exist.'); pause(); return
    try: targets=[path] if path.is_file() else list(path.iterdir())[:500]
    except OSError as e: print('[ERROR]',e); pause(); return
    rows=[]
    for item in targets:
        try:
            mode=stat.S_IMODE(item.stat().st_mode); row={'path':str(item),'mode':oct(mode),'other_write':bool(mode&stat.S_IWOTH),'group_write':bool(mode&stat.S_IWGRP),'directory':item.is_dir()}; rows.append(row)
            if row['other_write']: print('[!] World-writable:',oct(mode),item)
        except OSError as e: rows.append({'path':str(item),'error':str(e)})
    print(f'[+] Checked {len(rows)} item(s). Review findings in the report.'); report('permissions',{'root':str(path),'items':rows}); pause()

def dependency_check():
    heading('SYSTEM / Dependency & Root Check')
    info={'python':sys.version,'platform':platform.platform(),'uid':getattr(os,'getuid',lambda:None)(),'commands':{},'modules':{}}
    print('[ROOT]', 'yes' if info['uid']==0 else 'no / unavailable')
    for cmd in ('ip','ping','traceroute','tracepath','tcpdump','termux-info'):
        info['commands'][cmd]=shutil.which(cmd); print(f"[CMD] {cmd}: {info['commands'][cmd] or 'not installed'}")
    for mod in ('dns.resolver','scapy.all'):
        info['modules'][mod]=optional_import(mod) is not None; print(f"[PY] {mod}: {'available' if info['modules'][mod] else 'optional / missing'}")
    report('environment',info); pause()

# ============================ FORENSICS ============================
def file_hashes():
    heading('FORENSICS / File Hashes'); path=Path(ask('File path').strip('"')).expanduser()
    if not path.is_file(): print('[!] File not found.'); pause(); return
    hashes={name:hashlib.new(name) for name in ('md5','sha1','sha256','sha512')}
    try:
        with path.open('rb') as f:
            for chunk in iter(lambda:f.read(1024*1024),b''):
                for h in hashes.values(): h.update(chunk)
        data={'file':str(path),'size_bytes':path.stat().st_size,'hashes':{k:v.hexdigest() for k,v in hashes.items()}}
        print(json.dumps(data,indent=2)); report('file_hashes',data)
    except OSError as e: print('[ERROR]',e)
    pause()

def file_metadata():
    heading('FORENSICS / File Metadata'); path=Path(ask('File path').strip('"')).expanduser()
    try:
        st=path.stat(); data={'path':str(path.resolve()),'name':path.name,'size_bytes':st.st_size,'is_file':path.is_file(),'is_directory':path.is_dir(),'suffix':path.suffix,'modified':datetime.fromtimestamp(st.st_mtime).isoformat(),'created_or_changed':datetime.fromtimestamp(st.st_ctime).isoformat(),'permissions':oct(stat.S_IMODE(st.st_mode))}
        print(json.dumps(data,indent=2,ensure_ascii=False)); report('file_metadata',data)
    except OSError as e: print('[ERROR]',e)
    pause()

def hash_compare():
    heading('FORENSICS / SHA-256 File Comparison'); paths=[Path(ask('First file').strip('"')).expanduser(),Path(ask('Second file').strip('"')).expanduser()]
    if not all(p.is_file() for p in paths): print('[!] One or both files do not exist.'); pause(); return
    def digest(p):
        h=hashlib.sha256()
        with p.open('rb') as f:
            for chunk in iter(lambda:f.read(1024*1024),b''): h.update(chunk)
        return h.hexdigest()
    try:
        a,b=map(digest,paths); same=secrets.compare_digest(a,b); print('SHA-256 A:',a,'\nSHA-256 B:',b); print('[RESULT]', 'MATCH' if same else 'DIFFERENT')
        report('hash_compare',{'file_a':str(paths[0]),'sha256_a':a,'file_b':str(paths[1]),'sha256_b':b,'match':same})
    except OSError as e: print('[ERROR]',e)
    pause()

def log_analyzer():
    heading('FORENSICS / Basic Log Analyzer'); path=Path(ask('Log file path').strip('"')).expanduser()
    if not path.is_file(): print('[!] File not found.'); pause(); return
    terms=('error','failed','failure','denied','warning','critical','exception','unauthorized')
    counts={t:0 for t in terms}; matches=[]
    try:
        with path.open('r',encoding='utf-8',errors='replace') as f:
            for n,line in enumerate(f,1):
                low=line.lower()
                for t in terms:
                    if t in low: counts[t]+=1
                if any(t in low for t in terms) and len(matches)<300: matches.append({'line':n,'text':line.rstrip()[:500]})
        print('[COUNTS]'); [print(f'  {k}: {v}') for k,v in counts.items()]; print('[MATCHES]'); [print(f"{m['line']}: {m['text']}") for m in matches[:60]]
        report('log_analysis',{'file':str(path),'counts':counts,'matches':matches})
    except OSError as e: print('[ERROR]',e)
    pause()

def strings_extract():
    heading('FORENSICS / Printable String Extractor'); path=Path(ask('Binary or file path').strip('"')).expanduser()
    if not path.is_file(): print('[!] File not found.'); pause(); return
    minimum=ask('Minimum string length [6]') or '6'
    try: minimum=max(4,min(40,int(minimum)))
    except ValueError: minimum=6
    found=[]; buf=[]
    try:
        with path.open('rb') as f:
            while True:
                chunk=f.read(65536)
                if not chunk: break
                for b in chunk:
                    if 32<=b<=126: buf.append(chr(b))
                    else:
                        if len(buf)>=minimum: found.append(''.join(buf))
                        buf=[]
                        if len(found)>=2000: break
                if len(found)>=2000: break
        if len(buf)>=minimum and len(found)<2000: found.append(''.join(buf))
        print(f'[+] Extracted {len(found)} printable strings (limit 2000).'); [print(x[:240]) for x in found[:100]]
        report('strings',{'file':str(path),'count':len(found),'strings':found})
    except OSError as e: print('[ERROR]',e)
    pause()

# ============================ UTILITIES ============================
def url_tools():
    heading('UTILITIES / URL Parser & Encoder'); value=ask('URL or text')
    parsed=urllib.parse.urlparse(value)
    data={'input':value,'parsed':{'scheme':parsed.scheme,'hostname':parsed.hostname,'port':parsed.port,'path':parsed.path,'query':urllib.parse.parse_qs(parsed.query),'fragment':parsed.fragment},'encoded':urllib.parse.quote(value,safe=''),'decoded':urllib.parse.unquote(value)}
    print(json.dumps(data,indent=2,ensure_ascii=False)); report('url_tools',data); pause()

def password_generator():
    heading('UTILITIES / Secure Password Generator')
    try: length=int(ask('Length [24], 12–128') or '24')
    except ValueError: length=24
    if not 12<=length<=128: print('[!] Length must be 12–128.'); pause(); return
    alphabet=string.ascii_letters+string.digits+'!@#$%^&*()-_=+[]{}:,.?'
    password=''.join(secrets.choice(alphabet) for _ in range(length))
    print(paint(password,WHITE,True)); print('[i] Store it in a trusted password manager.'); pause()

def password_audit():
    heading('UTILITIES / Local Password Strength Check'); value=ask('Enter a test password (not stored or reported)')
    score=sum([len(value)>=12,len(value)>=16,any(c.islower() for c in value),any(c.isupper() for c in value),any(c.isdigit() for c in value),any(not c.isalnum() for c in value)])
    common={'password','password123','123456789','qwerty123','letmein','admin123'}
    if value.lower() in common: score=0
    label='WEAK' if score<=2 else 'FAIR' if score<=4 else 'STRONG'
    print(f'[RESULT] {label} ({score}/6 checks)')
    if len(value)<12: print('[!] Consider at least 12–16 characters.')
    if value.lower() in common: print('[!] This is a commonly used password pattern.')
    print('[i] This is a simple local heuristic, not a guarantee of security. The password is not saved.'); pause()

def checksum_text():
    heading('UTILITIES / Text SHA-256'); value=ask('Text to hash')
    digest=hashlib.sha256(value.encode()).hexdigest(); print('[SHA-256]',digest); pause()

# ----------------------------- MENU -----------------------------
SECTIONS={
 'NETWORK':[
  ('1','Local network overview',local_network),('2','Ping diagnostics (4 packets)',ping_diagnostics),('3','Traceroute',traceroute_diagnostics),('4','TCP port check (max 30)',tcp_port_check),('5','DNS lookup',dns_lookup),('6','PCAP analyzer / optional live capture',packet_analyzer)],
 'WEBSITE':[
  ('11','HTTP security headers',http_security_headers),('12','Website response and timing',website_health),('13','TLS certificate inspector',tls_inspector),('14','HTTP HEAD / OPTIONS inspector',http_methods),('15','robots.txt and sitemap',robots_sitemap),('16','Redirect destination check',url_redirect_trace)],
 'OSINT / SITES':[
  ('21','Domain profile / passive DNS',osint_domain_profile),('22','Passive subdomain discovery (CT logs)',passive_subdomains),('23','IP address profile',ip_address_profile),('24','Domain registration lookup (RDAP)',domain_rdap_lookup)],
 'OSINT / PEOPLE':[
  ('25','Public username footprint check',username_footprint),('26','Public people-search query builder',people_search_links),('27','Email syntax and domain check (no mailbox probing)',email_domain_check)],
 'OSINT / PROFILES':[
  ('28','Inspect public profile page metadata',public_profile_inspector)],
 'SYSTEM':[
  ('31','Device and Python overview',system_overview),('32','Visible process overview',process_overview),('33','File permission audit',permission_audit),('34','Dependency and root check',dependency_check)],
 'FORENSICS':[
  ('41','File hashes (MD5/SHA-1/SHA-256/SHA-512)',file_hashes),('42','File metadata',file_metadata),('43','Compare two files by SHA-256',hash_compare),('44','Basic log analyzer',log_analyzer),('45','Printable string extractor',strings_extract)],
 'UTILITIES':[
  ('51','URL parser / encoder / decoder',url_tools),('52','Secure password generator',password_generator),('53','Local password strength check',password_audit),('54','Text SHA-256 calculator',checksum_text)]}

def show_menu():
    clear(); banner()
    print(paint('\n  [ 00 ] Exit',RED,True))
    for section,items in SECTIONS.items():
        print(paint(f'\n  ┌─ {section}',DARK_RED,True))
        for key,label,_ in items: print(paint(f'  │ [{key}] {label}',RED))
    print(paint('\n  Reports are stored locally in ./indra_reports/',DARK_RED))
    print(paint('  Public-source OSINT only. No private-data scraping, exploit, brute-force, or DoS modules.',DIM))

def main():
    if os.name=='nt': os.system('')
    try:
        while True:
            show_menu(); choice=ask('Select a tool')
            if choice=='0': clear(); print(paint('INDRA // SESSION CLOSED',RED,True)); return
            action=next((fn for items in SECTIONS.values() for key,label,fn in items if key==choice),None)
            if not action: print('[!] Invalid option.'); time.sleep(.7); continue
            try: action()
            except KeyboardInterrupt: print('\n[!] Operation cancelled.'); pause()
            except Exception as e: print(f'\n[ERROR] {type(e).__name__}: {e}'); pause()
    finally: print(RESET,end='')

if __name__=='__main__': main()
