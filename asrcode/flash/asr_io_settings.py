"""Validated host serial options and deterministic operation-record paths."""
from pathlib import Path
import hashlib
import os

DEFAULT_BAUDRATE=115200
BAUDRATES=(9600,19200,38400,57600,115200,230400,460800,921600,
           1842000,1843200,2000000,3000000,3686400)


def baudrate_value(value=DEFAULT_BAUDRATE):
    if isinstance(value,bool) or not str(value).strip().isdigit():
        raise ValueError('波特率必须为300到4000000之间的整数')
    rate=int(str(value).strip())
    if not 300<=rate<=4000000:raise ValueError('波特率必须为300到4000000之间的整数')
    return rate


def records_root(anchor):
    return Path(anchor).resolve().parent/'读刷工具记录'


def read_state_dir(destination):
    identity=os.path.normcase(str(Path(destination).resolve()))
    key=hashlib.sha256(identity.encode('utf-8')).hexdigest()[:20]
    return records_root(destination)/'读取状态'/key


def read_paths(destination,state_dir=None):
    path=Path(destination)
    base=Path(state_dir)/path.name if state_dir is not None else path
    return {name:base.with_suffix(base.suffix+suffix) for name,suffix in
            [('resume','.resume.json'),('checkpoint','.checkpoint.json'),('result','.json')]}


def read_metadata_path(destination):
    central=read_paths(destination,read_state_dir(destination))['result']
    return central if central.exists() else read_paths(destination)['result']


def migrate_read_state(destination,state_dir):
    """Move old adjacent records only after checking all conflicts up front."""
    old=read_paths(destination);new=read_paths(destination,state_dir)
    for name,path in old.items():
        if path.exists() and new[name].exists() and path.read_bytes()!=new[name].read_bytes():
            raise ValueError('新旧读取记录冲突，请保留两份记录后重新选择输出文件')
    Path(state_dir).mkdir(parents=True,exist_ok=True)
    for name,path in old.items():
        if path.exists():
            if not new[name].exists():path.replace(new[name])
            else:
                duplicate=Path(state_dir)/'旧记录副本'/path.name
                duplicate.parent.mkdir(parents=True,exist_ok=True)
                if duplicate.exists() and duplicate.read_bytes()!=path.read_bytes():
                    raise ValueError('旧记录副本冲突，未覆盖已有记录')
                path.replace(duplicate)
    return new


def backend_run_dir(root,run_dir=None):
    root=Path(root).resolve()
    if run_dir is None:return None
    path=Path(run_dir).resolve()
    if root not in path.parents:
        raise ValueError('过程目录必须位于读刷工具记录目录内部')
    return path
