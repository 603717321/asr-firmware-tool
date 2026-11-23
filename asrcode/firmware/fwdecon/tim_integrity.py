"""Discover TIM 3.4 manifests, image SHA-256 fields, and RSA signatures."""
import hashlib
import re
import struct

DER_SHA256 = bytes.fromhex('3031300d060960864801650304020105000420')


def _u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def image_digest(data, start, length, digest_offset, *, self_image=False):
    payload = bytearray(data[start:start+length])
    if self_image:
        relative = digest_offset-start
        if relative < 0 or relative+32 > length:
            raise ValueError('TIM self digest lies outside hashed range')
        payload[relative:relative+32] = b'\x00'*32
    return hashlib.sha256(payload).digest()


def tables(data):
    result = []
    for match in re.finditer(b'HMIT', data):
        origin = match.start()-4
        if origin < 0 or origin % 4 or origin+56 > len(data):continue
        version, trusted, count = _u32(data, origin), _u32(data, origin+8), _u32(data, origin+44)
        if version != 0x00030400 or trusted not in (0, 1) or not 1 <= count <= 64:continue
        if origin+56+count*96 > len(data):continue
        entries = [];names = set();valid = True
        for index in range(count):
            at = origin+56+index*96
            ident, next_ident, start, load, size, hashed, algorithm = struct.unpack_from('<7I', data, at)
            try:name = data[at:at+4][::-1].decode('ascii')
            except UnicodeDecodeError:valid = False;break
            if not re.fullmatch('[A-Z0-9_]{4}', name) or name in names or not size or start+size > len(data) or hashed > size:
                valid = False;break
            if index == 0 and (not name.startswith('TIM') or start != origin or size < 56+count*96):
                valid = False;break
            if next_ident != (struct.unpack_from('<I', data, at+96)[0] if index+1 < count else 0xffffffff):
                valid = False;break
            names.add(name);digest = bytes(data[at+28:at+60])
            entry = {'name': name, 'descriptor': at, 'offset': start, 'load_address': load,
                     'size': size, 'hash_length': hashed, 'hash_algorithm': algorithm,
                     'digest_offset': at+28, 'digest': digest.hex()}
            if hashed and any(digest):
                entry['hash_valid'] = algorithm == 32 and digest == image_digest(data, start, hashed, at+28, self_image=index == 0)
            entries.append(entry)
        if not valid:continue
        own = entries[0];table = {'origin': origin, 'version': version, 'trusted': trusted,
                                'name': own['name'], 'size': own['size'], 'entries': entries}
        # TIM 3.4 RSA-2048 platform signature: reserved header, exponent,
        # modulus, signature. Infer offsets from the manifest's own lengths.
        signed_size = own['hash_length'];total = own['size']
        if trusted and signed_size >= 560 and total == signed_size+256:
            exponent_at = origin+signed_size-512;modulus_at = origin+signed_size-256
            ds = exponent_at-44
            if struct.unpack_from('<3I', data, ds) == (3, 32, 2048):
                exponent = int.from_bytes(data[exponent_at:exponent_at+256], 'little')
                modulus = int.from_bytes(data[modulus_at:modulus_at+256], 'little')
                signature_at = origin+signed_size
                if exponent >= 3 and exponent % 2 and modulus.bit_length() == 2048 and modulus % 2:
                    signature = {'signed_size': signed_size, 'exponent_offset': exponent_at,
                                 'modulus_offset': modulus_at, 'signature_offset': signature_at,
                                 'exponent': exponent, 'modulus': modulus}
                    actual = int.from_bytes(data[signature_at:signature_at+256], 'little')
                    encoded = pow(actual, exponent, modulus).to_bytes(256, 'big')
                    digest_info = DER_SHA256+hashlib.sha256(data[origin:origin+signed_size]).digest()
                    expected = b'\x00\x01'+b'\xff'*(256-len(digest_info)-3)+b'\x00'+digest_info
                    signature['valid'] = actual < modulus and encoded == expected
                    table['signature'] = signature
        result.append(table)
    return result


def checks(data):
    rows = []
    for table in tables(data):
        for entry in table['entries']:
            if 'hash_valid' in entry:
                rows.append((f"{table['name']}@0x{table['origin']:X}/{entry['name']} SHA-256",
                             entry['hash_valid'], f"0x{entry['offset']:X}+0x{entry['hash_length']:X}"))
        if 'signature' in table:
            rows.append((f"{table['name']}@0x{table['origin']:X} RSA-2048",table['signature']['valid'],''))
    return rows


def require_valid(data, reference=None):
    """Reject known invalid TIM images and lost manifest coverage."""
    target_tables = tables(data)
    if reference is not None:
        original = {(row['origin'], row['name'], len(row['entries'])) for row in tables(reference)}
        actual = {(row['origin'], row['name'], len(row['entries'])) for row in target_tables}
        if original != actual:
            raise ValueError('TIM清单结构改变或缺失，不能确认启动完整性')
    rows = checks(data)
    failures = [name for name, valid, note in rows if not valid]
    if failures:
        raise ValueError('启动完整性检查失败：' + '；'.join(failures) +
                         '。应用修改后须满足对应摘要和签名要求，禁止作为已验证固件输出或刷入。')
    return rows


def refresh(original, candidate, private_key=None, *, allow_key_replacement=False):
    if len(original) != len(candidate):raise ValueError('TIM refresh requires unchanged image size')
    manifests = tables(original);target = bytearray(candidate);events = []
    # Hash dependencies can include another manifest. Iterate until hashes and
    # signatures stop changing; reject cycles instead of publishing stale data.
    for iteration in range(max(2, len(manifests)*2+2)):
        before = bytes(target)
        for table in manifests:
            for entry in table['entries']:
                if not entry['hash_length'] or not any(bytes.fromhex(entry['digest'])):continue
                start = entry['offset'];end = start+entry['hash_length'];at = entry['digest_offset']
                if target[start:end] == original[start:end] and target[at:at+32] == original[at:at+32]:continue
                if entry['hash_algorithm'] != 32:raise ValueError('Unsupported TIM image hash algorithm')
                digest = image_digest(target, start, entry['hash_length'], at, self_image=entry is table['entries'][0])
                if target[at:at+32] != digest:
                    target[at:at+32] = digest;events.append({'table':table['origin'],'image':entry['name'],'digest_offset':at})
            own = table['entries'][0];covered = own['hash_length']
            if not covered or target[table['origin']:table['origin']+covered] == original[table['origin']:table['origin']+covered]:continue
            if not table['trusted']:continue
            signature = table.get('signature')
            if not signature:raise ValueError('Changed trusted TIM has unsupported signature layout')
            if private_key is None:raise ValueError('Changing this image requires TIM RSA re-signing; no private key provided')
            numbers = private_key.private_numbers();public = numbers.public_numbers
            if private_key.key_size != 2048 or public.e != signature['exponent']:
                raise ValueError('TIM requires RSA-2048 with the original public exponent')
            if public.n != signature['modulus'] and not allow_key_replacement:
                raise ValueError('Signing key does not match original TIM public key')
            at = signature['modulus_offset'];target[at:at+256] = public.n.to_bytes(256,'little')
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding
            message = bytes(target[table['origin']:table['origin']+covered])
            signed = private_key.sign(message,padding.PKCS1v15(),hashes.SHA256())
            at = signature['signature_offset'];target[at:at+256] = signed[::-1]
        if bytes(target) == before:break
    else:raise ValueError('TIM integrity dependency did not converge')
    failures = [name for name,valid,note in checks(target) if not valid]
    if failures:raise ValueError('TIM integrity validation failed: '+', '.join(failures))
    return bytes(target), events
