from pathlib import Path

class OperationCancelled(RuntimeError):
    pass

def check_stop(path):
    if path and Path(path).exists():
        raise OperationCancelled("Stop requested")
