"""Generic source-to-device TIM partition layout validation."""
import re
import struct


TIM_VERSION = 0x00030400
TIM_HEADER_SIZE = 56
TIM_ENTRY_SIZE = 96


def source_partition_layout(image, name, offset, length):
    """Locate the unique source TIM table that declares the selected extent.

    A ``None`` result means the partition was discovered by a non-TIM fallback,
    such as CPZ metadata. The caller then keeps its existing structural guard.
    """
    from asrcode.firmware.fwdecon.tim_integrity import tables

    target = str(name).upper()
    exact = []
    named = []
    for table in tables(image):
        for entry in table['entries']:
            if entry['name'].upper() != target:
                continue
            row = {
                'partition_name': entry['name'].upper(),
                'partition_offset': int(entry['offset']),
                'partition_size': int(entry['size']),
                'manifest_origin': int(table['origin']),
                'manifest_name': str(table['name']).upper(),
                'source_entry_count': len(table['entries']),
            }
            named.append(row)
            if row['partition_offset'] == offset and row['partition_size'] == length:
                exact.append(row)
    if not named:
        return None
    if len(exact) != 1:
        raise ValueError(
            f'{target} source TIM declaration is not unique for '
            f'{offset:#x}+{length:#x}'
        )
    return exact[0]


def _decode_name(raw):
    try:
        name = raw[::-1].decode('ascii')
    except UnicodeDecodeError as exc:
        raise ValueError('TIM contains a non-ASCII image name') from exc
    if not re.fullmatch(r'[A-Z0-9_]{4}', name):
        raise ValueError(f'Invalid TIM image name: {name!r}')
    return name


def parse_device_manifest(data, origin, flash_size):
    """Parse one isolated TIM 3.4 table whose image offsets stay absolute."""
    if len(data) < TIM_HEADER_SIZE:
        raise ValueError('Device TIM header is incomplete')
    version, magic, trusted = struct.unpack_from('<I4sI', data, 0)
    count = struct.unpack_from('<I', data, 44)[0]
    if version != TIM_VERSION or magic != b'HMIT' or trusted not in (0, 1):
        raise ValueError(f'No valid TIM 3.4 manifest at {origin:#x}')
    if not 1 <= count <= 64:
        raise ValueError(f'Invalid TIM entry count at {origin:#x}: {count}')
    table_size = TIM_HEADER_SIZE + count * TIM_ENTRY_SIZE
    if table_size > flash_size - origin or len(data) < table_size:
        raise ValueError('Device TIM entries are incomplete')

    rows = []
    names = set()
    for index in range(count):
        at = TIM_HEADER_SIZE + index * TIM_ENTRY_SIZE
        ident, next_ident, start, load, size, hashed, algorithm = struct.unpack_from('<7I', data, at)
        name = _decode_name(data[at:at + 4])
        if name in names:
            raise ValueError(f'Duplicate TIM image name: {name}')
        if not size or start + size > flash_size or hashed > size:
            raise ValueError(f'Invalid TIM extent for {name}: {start:#x}+{size:#x}')
        if index == 0 and (not name.startswith('TIM') or start != origin or size < table_size):
            raise ValueError(f'Invalid TIM self entry at {origin:#x}')
        if any(start < row['offset'] + row['size'] and row['offset'] < start + size for row in rows):
            raise ValueError(f'Overlapping TIM extent for {name}: {start:#x}+{size:#x}')
        expected_next = struct.unpack_from('<I', data, at + TIM_ENTRY_SIZE)[0] if index + 1 < count else 0xffffffff
        if next_ident != expected_next:
            raise ValueError(f'Broken TIM image chain after {name}')
        names.add(name)
        rows.append({
            'name': name,
            'offset': start,
            'load_address': load,
            'size': size,
            'hash_length': hashed,
            'hash_algorithm': algorithm,
            'ident': ident,
        })
    return {
        'origin': origin,
        'name': rows[0]['name'],
        'entry_count': count,
        'table_size': table_size,
        'entries': rows,
    }


def validate_device_partition(q, layout, offset, length):
    """Read only the source-declaring TIM table and compare its target extent."""
    if layout is None:
        raise ValueError('A source TIM layout is required')
    expected = (int(layout['partition_offset']), int(layout['partition_size']))
    if expected != (offset, length):
        raise ValueError(
            f"{layout['partition_name']} input extent changed after source parsing: "
            f'{offset:#x}+{length:#x}, expected {expected[0]:#x}+{expected[1]:#x}'
        )
    origin = int(layout['manifest_origin'])
    flash_size = int(getattr(q, 'flash_size', 0x1000000))
    if origin < 0 or origin + TIM_HEADER_SIZE > flash_size:
        raise ValueError(f'Source TIM location is outside device Flash: {origin:#x}')
    header = q.stable_mapped_block(origin, TIM_HEADER_SIZE)
    if len(header) != TIM_HEADER_SIZE:
        raise ValueError('Device TIM header read is incomplete')
    count = struct.unpack_from('<I', header, 44)[0]
    if not 1 <= count <= 64:
        raise ValueError(f'Invalid TIM entry count at {origin:#x}: {count}')
    table_size = TIM_HEADER_SIZE + count * TIM_ENTRY_SIZE
    manifest = parse_device_manifest(
        q.stable_mapped_block(origin, table_size), origin, flash_size
    )
    if manifest['name'] != str(layout['manifest_name']).upper():
        raise ValueError(
            f"TIM identity mismatch at {origin:#x}: source {layout['manifest_name']}, "
            f"device {manifest['name']}"
        )
    rows = [row for row in manifest['entries'] if row['name'] == layout['partition_name']]
    if len(rows) != 1:
        raise ValueError(
            f"Device TIM at {origin:#x} must contain exactly one "
            f"{layout['partition_name']} image"
        )
    actual = (rows[0]['offset'], rows[0]['size'])
    if actual != expected:
        raise ValueError(
            f"{layout['partition_name']} layout mismatch: input "
            f"({expected[0]:#x}, {expected[1]:#x}), device "
            f"({actual[0]:#x}, {actual[1]:#x})"
        )
    return {
        'method': 'source_declaring_TIM',
        'manifest_origin': origin,
        'manifest_name': manifest['name'],
        'partition_name': rows[0]['name'],
        'offset': rows[0]['offset'],
        'size': rows[0]['size'],
        'device_entry_count': manifest['entry_count'],
    }
