"""Lazy IP discovery: explicit address first, then bounded local device gateways."""
import ipaddress
import re

def automatic_exclusion(row):
    address=ipaddress.IPv4Address(row['ip'])
    if address in ipaddress.IPv4Network('198.18.0.0/15'):
        return '基准测试/代理地址'
    text=' '.join(str(row.get(key) or '') for key in ('interface','description')).lower()
    # RNDIS/USB NICs can be software interfaces too. Do not reject all virtual NICs.
    if re.search(r'\b(?:meta|mihomo|clash|wintun|wireguard|openvpn|tailscale|zerotier|vpn|tun|tap)\b|tap-windows|hyper-v|vmware|virtualbox|loopback',text):
        return '虚拟/隧道网卡'
    return ''

def iter_ip_candidates(manual,discover_gateways,emit=lambda line:None,cancel=lambda:False):
    from asrcode.flash.asr_probe import normalize_ip
    seen=set()
    if str(manual or '').strip():
        try:address=normalize_ip(manual)
        except ValueError as exc:emit('输入地址：'+str(exc))
        else:
            if cancel():return
            seen.add(address)
            yield {'ip':address,'interface':'手动输入'}
    # Deliberately deferred until the explicit address has failed or mismatched.
    if cancel():return
    try:gateways=discover_gateways()
    except Exception as exc:
        emit('网关发现：'+str(exc));return
    for row in gateways:
        if cancel():return
        try:address=normalize_ip(row.get('ip'))
        except (ValueError,TypeError):continue
        if not address or address in seen:continue
        candidate={**row,'ip':address}
        reason=automatic_exclusion(candidate)
        if reason:
            emit('跳过自动候选：'+address+'（'+str(row.get('interface') or '')+'，'+reason+'）')
            continue
        if len(seen)>=16:return
        seen.add(address)
        yield candidate

def should_finish_web(item,expected_imei=''):
    if not item.get('success'):return False
    return not expected_imei or item.get('imei')==expected_imei
