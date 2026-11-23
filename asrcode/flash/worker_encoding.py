"""Explicit UTF-8 pipe contract, including frozen Python interpreters."""
import sys
def configure_worker_streams():
    for name in ('stdout','stderr'):
        stream=getattr(sys,name,None)
        if stream is not None and hasattr(stream,'reconfigure'):
            stream.reconfigure(encoding='utf-8',errors='backslashreplace',line_buffering=True)
