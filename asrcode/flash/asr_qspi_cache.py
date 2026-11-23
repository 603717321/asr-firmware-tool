"""Invalidate FSL QSPI AHB buffers using the firmware driver's reset pulse."""
import time


def invalidate_ahb(qspi, delay=time.sleep):
    profile = getattr(qspi, 'profile', {})
    if profile.get('controller') != 'fsl_qspi_nor' or profile.get('base') != 0xd420b000:
        raise ValueError('AHB reset requires a verified FSL QSPI profile')
    qspi.wait_idle()
    if qspi.flash_ready() & 1:
        raise RuntimeError('NOR is still busy before AHB invalidation')
    original = qspi.read(0)
    if original & 3:
        raise RuntimeError('QSPI reset already active')
    # Native firmware: MCR |= 3, delay, MCR &= ~3. Release the reset even
    # when the transport reports an error after the assertion was delivered.
    try:
        qspi.write(0, original | 3)
        delay(.001)
    finally:
        qspi.write(0, original)
        for name in ('_guard_snapshot', '_idle_snapshot'):
            if hasattr(qspi, name):
                setattr(qspi, name, None)
    qspi.wait_idle()
    if qspi.read(0) & 3:
        raise RuntimeError('QSPI reset did not release')
    qspi._needs_ahb_invalidation = False
    qspi.ahb_invalidations = getattr(qspi, 'ahb_invalidations', 0) + 1
    if hasattr(qspi, 'events'):
        qspi.events.append({'ahb_invalidation': True, 'mcr_before': hex(original)})
