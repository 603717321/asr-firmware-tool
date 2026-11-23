"""Reopen a failed controller session, requiring immutable Flash identity match."""
def reopen_conservative(writer,factory,port,baudrate,records_dir):
    expected_id=bytes(writer.jedec_id);expected_size=writer.flash_size
    if not expected_id or expected_id[0] in (0,255) or expected_size<=0:
        raise RuntimeError('Cannot recover without previously verified Flash identity')
    writer.close()
    candidate=factory(port,baudrate=baudrate,records_dir=records_dir)
    try:
        candidate.check_profile()
        if bytes(candidate.jedec_id)!=expected_id or candidate.flash_size!=expected_size:
            raise RuntimeError('Flash identity changed while reopening controller session; stopped')
        return candidate
    except Exception:
        candidate.close();raise
