"""Validate explicitly bounded configuration images against their snapshot."""
import hashlib
import json
from pathlib import Path


def load_policy(path,data):
    meta_path=Path(path).with_suffix('.说明.json')
    if not meta_path.exists():return None
    meta=json.loads(meta_path.read_text(encoding='utf-8'))
    if meta.get('scope')!='configuration_only':return None
    if hashlib.sha256(data).hexdigest()!=meta.get('output_sha256'):
        raise ValueError('配置镜像与说明校验不匹配，请重新生成配置镜像')
    ranges=meta.get('allowed_write_ranges')
    if not isinstance(ranges,list) or not ranges:
        raise ValueError('旧配置镜像缺少当前快照的写入范围与基线校验；请基于当前设备快照重新生成配置镜像，避免覆盖身份/校准区')
    blocks={}
    for row in ranges:
        start=int(row['offset'],0) if isinstance(row['offset'],str) else row['offset']
        size=row['length']
        if start%4096 or size!=4096 or not 0<=start<=len(data)-size or start in blocks:
            raise ValueError('配置写入范围无效')
        expected=row.get('source_sha256','')
        if len(expected)!=64 or any(c not in '0123456789abcdef' for c in expected):
            raise ValueError('配置块缺少有效源快照校验值')
        blocks[start]=expected
    return {'blocks':blocks,'source_sha256':meta.get('source_sha256'),
            'scope':'configuration_only','sidecar':str(meta_path)}


def validate_block(policy,offset,observed,target):
    if offset not in policy['blocks']:raise ValueError('请求超出声明配置块范围')
    if observed==target:return
    if hashlib.sha256(observed).hexdigest()!=policy['blocks'][offset]:
        raise RuntimeError(f'配置基线已变化 {offset:#x}；未擦写，请重新读取设备并生成配置镜像')
