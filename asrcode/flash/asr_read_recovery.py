"""Recover complete read transactions; never trim guessed URCs from Flash data."""
import json
from asrcode.flash.operation_control import OperationCancelled

class RecoveringBinaryReader:
    def __init__(self,native,synchronize,mapped,check,stats,emit=print):
        self.native=native;self.synchronize=synchronize;self.mapped=mapped
        self.check=check;self.stats=stats;self.emit=emit
        self.chunk_size=4096;self.force_mapped=False

    def event(self,action,address,**details):
        self.emit('READ_RECOVERY '+json.dumps({'action':action,'address':address,**details},ensure_ascii=False))

    def conservative(self,address):
        self.chunk_size=min(self.chunk_size,256)
        self.event('smaller_frames',address,chunk_size=self.chunk_size)

    def mapped_only(self,address):
        self.force_mapped=True
        self.stats['mapped_fallbacks']=self.stats.get('mapped_fallbacks',0)+1
        self.event('mapped_fallback',address)

    def read(self,address,length):
        if self.force_mapped:
            self.check();return self.mapped(address,length)
        last=None
        sizes=[self.chunk_size,self.chunk_size,min(self.chunk_size,1024),min(self.chunk_size,256)]
        for attempt,size in enumerate(sizes):
            self.check()
            try:
                if attempt:self.synchronize()
                data=bytearray()
                while len(data)<length:
                    self.check();amount=min(size,length-len(data))
                    block=self.native.read(address+len(data),amount)
                    if len(block)!=amount:raise RuntimeError('Binary read returned a short block')
                    data.extend(block)
                if attempt:
                    self.chunk_size=size
                    self.stats['recovered_reads']=self.stats.get('recovered_reads',0)+1
                    self.event('recovered',address,attempt=attempt+1,chunk_size=size)
                return bytes(data)
            except OperationCancelled:raise
            except (RuntimeError,OSError) as exc:
                # The whole candidate is discarded, including good fragments before the failure.
                last=str(exc)
                self.stats['transport_retries']=self.stats.get('transport_retries',0)+1
                self.event('discard_frame',address,attempt=attempt+1,chunk_size=size,error=last)
        self.check()
        self.synchronize()
        self.mapped_only(address)
        # The outer VerifiedReader still compares two complete observations when enabled.
        return self.mapped(address,length)


def diagnostic_paths(result):
    from pathlib import Path
    folder=result.get('run_dir')
    paths=[]
    if folder:
        paths.extend([('原始日志',str(Path(folder)/'operation.log')),('任务结果',str(Path(folder)/'result.json'))])
    if result.get('backend_result'):paths.append(('读取详情',result['backend_result']))
    return paths
