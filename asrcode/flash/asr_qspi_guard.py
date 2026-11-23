"""Guard shared QSPI hardware using fresh MMIO, never serial-owner tokens."""
import struct


def restore_lut(qspi, required):
    """Restore overwritten QSPI LUT registers and retain lock state."""
    if hasattr(qspi, 'wait_idle'):
        qspi.wait_idle()
    lock = qspi.read(0x304) if hasattr(qspi, 'read') else 1
    try:
        if hasattr(qspi, 'write'):
            qspi.write(0x300, 0x5af05af0)
            qspi.write(0x304, 2)
            for off, val in required.items():
                qspi.write(off, val)
    finally:
        if hasattr(qspi, 'write'):
            qspi.write(0x300, 0x5af05af0)
            qspi.write(0x304, lock)


def command_guard(qspi, required):
    addresses = [0xd420b15c, 0xd420b160] + [0xd420b000 + off for off in required]
    observed = struct.unpack('<' + 'I' * len(addresses), qspi.read_addresses(addresses))
    status, flags = observed[:2]
    if list(observed[2:]) != list(required.values()):
        if hasattr(qspi, 'write') and hasattr(qspi, 'read'):
            try:
                restore_lut(qspi, required)
                observed = struct.unpack('<' + 'I' * len(addresses), qspi.read_addresses(addresses))
                status, flags = observed[:2]
            except Exception:
                pass
        if list(observed[2:]) != list(required.values()):
            raise RuntimeError('QSPI LUT changed; stopped before write')
    if status & 1:
        qspi.wait_idle()
        qspi.check_lut(required)
    return status, flags
