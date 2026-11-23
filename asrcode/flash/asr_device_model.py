"""ASR device model resolution and background web calibration engine.

Provides multi-tiered device model discovery and validation:
1. Web Asset Calibration: In-depth inspection of web frontend UI scripts (home.card.model).
2. XML Identity Parsing: hardware_version, model_name, device_name from home_data/status1/sysinfo.
3. Version Heuristics: Pattern extraction from version_num (e.g. WY-M8-3S-20260314-MQTT-YHYW001 -> M8-3s).
4. Firmware Image Cross-Validation: Alignment between loaded firmware and hardware identity.
"""
import re
import urllib.parse
import urllib.request


def extract_model_from_web_assets(ip, opener=None, timeout=3):
    """Calibrate device model directly from the web management frontend scripts."""
    if not ip:
        return ''
    ip = str(ip).strip()
    if '://' in ip:
        ip = urllib.parse.urlsplit(ip).hostname or ip
    if opener is None:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        url = f'http://{ip}/'
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with opener.open(req, timeout=timeout) as resp:
            html = resp.read(65536).decode('utf-8', errors='replace')
        scripts = re.findall(r'<script\b[^>]*\bsrc=["\']([^"\']+)["\']', html, re.I)
        for s in scripts[:5]:
            script_url = urllib.parse.urljoin(url, s)
            parsed = urllib.parse.urlsplit(script_url)
            if parsed.hostname != ip:
                continue
            req_s = urllib.request.Request(script_url, headers={'User-Agent': 'Mozilla/5.0'})
            try:
                with opener.open(req_s, timeout=timeout) as resp_s:
                    code = resp_s.read(2 * 1024 * 1024).decode('utf-8', errors='replace')
            except Exception:
                continue
            # Pattern 1: Vue template rendering home.card.model with info-value
            # e.g.: Ho("span",xF,J(Tt(a)("home.card.model"))+":",1),Ho("span",{class:"info-value"},J("M8-3s"))
            m = re.search(r'home\.card\.model.{1,120}?class:\s*["\']info-value["\'].{1,60}?J\(\s*["\']([^"\']+)["\']\s*\)', code, re.S)
            if m:
                val = m.group(1).strip()
                if val:
                    return normalize_model_name(val)
            # Pattern 2: card.model text followed by J("model")
            m2 = re.search(r'["\']home\.card\.model["\']\)\s*\+\s*["\']:\s*["\'].{1,100}?J\(\s*["\']([^"\']+)["\']\s*\)', code, re.S)
            if m2:
                val = m2.group(1).strip()
                if val:
                    return normalize_model_name(val)
            # Pattern 3: Explicit assignment or declaration: deviceModel = "M8-3s"
            m3 = re.search(r'(?:deviceModel|hardware_version|product_model)\s*[:=]\s*["\']([^"\']+)["\']', code, re.I)
            if m3:
                val = m3.group(1).strip()
                if val:
                    return normalize_model_name(val)
    except Exception:
        pass
    return ''


def normalize_model_name(model_str):
    """Normalize model string casing and representation."""
    if not model_str:
        return ''
    raw = str(model_str).strip()
    # Normalize M8-3s / M8-3S to standard M8-3s
    if re.match(r'(?i)^M8-3S$', raw):
        return 'M8-3s'
    # Normalize MF801, MF811, MF813, MZ808, U10LS
    m_upper = raw.upper()
    for prefix in ('MF801', 'MF811', 'MF813', 'MZ808', 'U10LS', 'NZ_SSG_V20'):
        if prefix in m_upper:
            return prefix
    return raw


def resolve_model_from_version(version_str):
    """Extract model name from firmware version string."""
    if not version_str:
        return ''
    v = str(version_str).strip()
    # Specific M8-3s match
    if re.search(r'(?i)\bM8-3S\b', v) or re.search(r'(?i)WY-M8-3S', v):
        return 'M8-3s'
    # Generic WY prefix: WY-<MODEL>-YYYYMMDD
    m_wy = re.search(r'(?i)^WY-([A-Za-z0-9_]+-[A-Za-z0-9_]+)-\d{8}', v)
    if m_wy:
        return normalize_model_name(m_wy.group(1))
    # Standard models in version string
    for model in ('MF801', 'MF811', 'MF813', 'MZ808', 'U10LS', 'NZ_SSG_V20'):
        if model.lower() in v.lower():
            return model
    return ''


def resolve_device_model(values=None, web_ip=None, serial_info=None, image_info=None, opener=None):
    """Multi-tiered resolution of device model."""
    values = values or {}
    serial_info = serial_info or {}
    image_info = image_info or {}

    # 1. Tier 1: Ground truth from web background calibration
    if web_ip:
        web_asset_model = extract_model_from_web_assets(web_ip, opener=opener)
        if web_asset_model:
            return web_asset_model

    # 2. Tier 2: XML hardware_version or model_name tags
    for key in ('hardware_version', 'model_name', 'device_name', 'device_model', 'product_name'):
        tag_val = values.get(key)
        if tag_val and tag_val.strip() and tag_val.strip() not in ('未返回型号', '未识别', 'Nezha_MIFI'):
            return normalize_model_name(tag_val.strip())

    # 3. Tier 3: Version string from web sysinfo/home_data
    web_ver = values.get('version_num') or values.get('version')
    if web_ver:
        m_web = resolve_model_from_version(web_ver)
        if m_web:
            return m_web

    # 4. Tier 4: Serial info (version or image correlation)
    ser_ver = serial_info.get('version')
    if ser_ver:
        m_ser = resolve_model_from_version(ser_ver)
        if m_ser:
            return m_ser

    # 5. Tier 5: Serial version correlation with loaded firmware image
    img_ver = image_info.get('version', '')
    if ser_ver and img_ver and ser_ver in img_ver:
        m_img = resolve_model_from_version(img_ver) or image_info.get('model')
        if m_img:
            return m_img

    # 6. Tier 6: Loaded firmware image directly
    if image_info.get('model'):
        return normalize_model_name(image_info['model'])
    if img_ver:
        m_img = resolve_model_from_version(img_ver)
        if m_img:
            return m_img

    return ''


def extract_firmware_version_and_model(data, filename=''):
    """Extract canonical version string and model from binary firmware image."""
    versions = re.findall(rb'(?:WY|MF|MZ|NZ|U10)[0-9A-Za-z_-]{6,90}', data)
    decoded_versions = [v.decode('ascii', errors='ignore').strip() for v in versions]

    # Prioritize version with date or _V or WY
    canonical_ver = ''
    for v in decoded_versions:
        if 'WY-M8-3S' in v or re.search(r'WY-[A-Za-z0-9_-]+-\d{8}', v):
            canonical_ver = v
            break
        if '_V' in v or re.search(r'\d{8}', v):
            if not canonical_ver:
                canonical_ver = v

    if not canonical_ver and decoded_versions:
        canonical_ver = decoded_versions[0]

    # Fallback to filename if binary lacked a clear version tag
    if not canonical_ver and filename:
        m_fn = re.search(r'((?:WY|MF|MZ|NZ|U10)[0-9A-Za-z_-]{6,90})', str(filename))
        if m_fn:
            canonical_ver = m_fn.group(1)

    model = resolve_model_from_version(canonical_ver)
    if not model and filename:
        model = resolve_model_from_version(str(filename))

    return canonical_ver or '镜像中未识别', model or ''
