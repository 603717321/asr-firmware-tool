"""Bounded read-only discovery; endpoints come from the host network or user."""
import ipaddress
import json
import os
import subprocess
import urllib.parse
import urllib.request
import re
import xml.etree.ElementTree as ET


def normalize_ip(value):
    value=str(value or '').strip()
    if not value:return ''
    parsed=urllib.parse.urlsplit(value if '://' in value else 'http://'+value)
    if parsed.scheme!='http' or parsed.username or parsed.password or parsed.port not in (None,80):
        raise ValueError('请输入设备 IPv4 地址，或 http://IPv4 地址')
    address=ipaddress.IPv4Address(parsed.hostname or '')
    if address.is_unspecified or address.is_multicast or address.is_loopback:
        raise ValueError('无效的设备 IPv4 地址')
    return str(address)


def discover_gateways():
    """Discover default IPv4 gateways across Windows 7, 8, 8.1, 10, 11 reliably without crashing."""
    if os.name != 'nt':
        return []
    found = []
    seen = set()

    # Tier 1: Fast, universal ipconfig /all (runs on every Windows NT release since Win2000)
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= getattr(subprocess, 'STARTF_USESHOWWINDOW', 1)
        raw = subprocess.check_output(
            'ipconfig /all',
            startupinfo=startupinfo,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            timeout=8
        ).decode('gbk', errors='replace')

        sections = re.split(r'\r?\n\r?\n', raw)
        for sec in sections:
            desc_m = re.search(r'(?:描述|Description)[ .]*:\s*([^\r\n]+)', sec)
            desc = desc_m.group(1).strip() if desc_m else ''
            iface_m = re.search(r'^[^\r\n:]+适配器\s+([^:\r\n]+):', sec.strip(), re.M)
            iface = iface_m.group(1).strip() if iface_m else desc

            gw_match = re.search(r'(?:默认网关|Default Gateway)[ .]*:\s*([0-9a-fA-F:.]+)', sec)
            if gw_match:
                lines = sec[gw_match.start():].splitlines()
                for line in lines[:6]:
                    for ip_str in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line):
                        try:
                            ip = normalize_ip(ip_str)
                            if ip and ip not in seen:
                                seen.add(ip)
                                found.append({'ip': ip, 'interface': iface, 'description': desc})
                        except Exception:
                            pass
    except Exception:
        pass

    # Tier 2: route print 0.0.0.0 fallback (captures default routes on Win7/8/10/11)
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= getattr(subprocess, 'STARTF_USESHOWWINDOW', 1)
        route_out = subprocess.check_output(
            'route print 0.0.0.0',
            startupinfo=startupinfo,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            timeout=5
        ).decode('gbk', errors='replace')

        for line in route_out.splitlines():
            parts = line.strip().split()
            if len(parts) >= 5 and parts[0] == '0.0.0.0' and parts[1] == '0.0.0.0':
                gw_str = parts[2]
                try:
                    ip = normalize_ip(gw_str)
                    if ip and ip not in seen:
                        seen.add(ip)
                        found.append({'ip': ip, 'interface': '默认路由', 'description': 'IPv4 缺省网关'})
                except Exception:
                    pass
    except Exception:
        pass

    return sorted(
        found,
        key=lambda row: (
            not any(s in str(row.get('description', '')).lower() for s in ('rndis', 'ndis', 'usb', 'mobile', 'lan')),
            row.get('ip', '')
        )
    )


def ip_candidates(manual,gateways):
    rows=[];seen=set()
    if manual:
        rows.append({'ip':normalize_ip(manual),'interface':'手动输入'})
    rows.extend(gateways)
    result=[]
    for row in rows:
        address=normalize_ip(row['ip'])
        if address not in seen:
            seen.add(address);result.append({**row,'ip':address})
    return result[:16]


def has_asr_web(ip):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        norm_ip = normalize_ip(ip)
        with opener.open('http://' + norm_ip + '/', timeout=2) as response:
            final = urllib.parse.urlsplit(response.geturl())
            if final.hostname != norm_ip:
                return False
            html = response.read(32768)
            body = html.lower()
    except Exception:
        return False

    if any(marker in body for marker in (b'js/base/ajax_calls.js', b'xml_action.cgi', b'g_platformname')):
        return True

    scripts = re.findall(rb'<script\b[^>]*\bsrc=["\']([^"\']+)["\']', html, re.I)
    for script in scripts[:3]:
        try:
            url = urllib.parse.urljoin('http://' + norm_ip + '/', script.decode('utf-8', errors='replace'))
            parsed = urllib.parse.urlsplit(url)
            if parsed.scheme != 'http' or parsed.hostname != norm_ip or parsed.port not in (None, 80):
                continue
            with opener.open(url, timeout=3) as response:
                final = urllib.parse.urlsplit(response.geturl())
                if final.hostname != norm_ip:
                    continue
                code = response.read(2 * 1024 * 1024).lower()
            if b'xml_action.cgi' in code and b'login.cgi' in code:
                return True
        except Exception:
            continue
    return False


def query_device_info(client):
    """Support legacy status1 and the frontend-discovered home_data XML layout."""
    values={};sources=[];attempts=[]
    for name in ('status1','home_data','version_num'):
        status,body=client.get(name)
        attempts.append({'file':name,'status':status})
        if status!=200:continue
        try:
            root=ET.fromstring(body)
        except ET.ParseError:continue
        if root.tag.rsplit('}',1)[-1]!='RGW':continue
        result={node.tag.rsplit('}',1)[-1]:node.text.strip() for node in root.iter()
                if not list(node) and node.text and node.text.strip()}
        if result.get('login_status','').upper()=='UNAUTHORIZED':continue
        keys=('hardware_version','model_name','version_num','IMEI','imei')
        if not any(result.get(key) for key in keys):continue
        values.update(result);sources.append(name)
        if name=='status1' or values.get('version_num'):break
    if values and not (values.get('hardware_version') or values.get('model_name')):
        try:
            from asrcode.flash.asr_device_model import resolve_device_model
            ip = getattr(client, 'host', None)
            if not ip and hasattr(client, 'base'):
                ip = urllib.parse.urlsplit(client.base).hostname
            model = resolve_device_model(values=values, web_ip=ip)
            if model:
                values['hardware_version'] = model
                values['model_name'] = model
        except Exception:
            pass
    return values,'+'.join(sources),attempts


def at_version_text(reply,command='AT+CGMR'):
    lines=[]
    for line in reply.replace('\r','\n').splitlines():
        line=line.strip()
        if not line or line.upper() in (command.upper(),'OK'):continue
        if line.upper().startswith('+CGMR:'):line=line.split(':',1)[1].strip().strip('"')
        lines.append(line)
    return '\n'.join(lines)
