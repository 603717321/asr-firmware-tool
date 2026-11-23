"""User-facing transfer progress; raw backend traces remain unchanged."""
import re

def duration(seconds):
    if seconds is None:return '计算中'
    seconds=max(0,int(seconds));minutes,seconds=divmod(seconds,60);hours,minutes=divmod(minutes,60)
    return f'{hours:02d}:{minutes:02d}:{seconds:02d}'

class TransferLog:
    def __init__(self):
        self.previous={}
        self.blocks=False

    def progress(self,line,resumed=0):
        block=re.fullmatch(r'BLOCK_PROGRESS (\d+)/(\d+) sector=(0x[0-9a-fA-F]+) inst=([\d.]+) overall=([\d.]+) elapsed=([\d.]+)',line)
        read=re.fullmatch(r'READ (0x[0-9a-fA-F]+)/(0x[0-9a-fA-F]+) elapsed=([\d.]+)s?',line)
        write=re.fullmatch(r'WRITE_SPEED (\d+)/(\d+) elapsed=([\d.]+)',line)
        stage=re.fullmatch(r'PROGRESS (compare|verify|preflight) (\d+)/(\d+)',line)
        if write and self.blocks:return {'handled':True}
        if not any((block,read,write,stage)):return None
        if block:
            self.blocks=True
            done,total=int(block[1]),int(block[2]);elapsed=float(block[6]);phase='写入'
            speed=float(block[5])*1024
            remaining=(max(0,total-done)*4096/speed) if speed else None
            detail=f'{done:,}/{total:,} 块'
        elif read or write:
            match=read or write;base=16 if read else 10
            phase='读取' if read else '写入';done,total=int(match[1],base),int(match[2],base)
            elapsed=float(match[3]);speed=max(0,done-resumed)/elapsed if elapsed>0 else 0
            remaining=max(0,total-done)/speed if speed else None
            detail=f'{done/1048576:.2f}/{total/1048576:.2f} MiB'
        else:
            phase={'compare':'差异扫描','verify':'回读校验','preflight':'写前检查'}[stage[1]]
            done,total=int(stage[2]),int(stage[3]);elapsed=None;speed=None;remaining=None
            detail=f'{done/1048576:.2f}/{total/1048576:.2f} MiB'
        percent=min(100,done*100//max(1,total))
        status=f'{phase} {percent:3d}% · {detail}'
        if speed is not None:
            remaining=0 if done>=total else remaining
            status+=f' · {speed/1024:.1f} KiB/s · 剩余 {duration(remaining)}'
        previous=self.previous.get(phase)
        emit=previous is None or percent>=previous[0]+5 or (elapsed is not None and elapsed-previous[1]>=3) or (done>=total and previous[2]<total)
        # Duplicate final markers and repeated samples never add duplicate logs.
        if previous and done==previous[2]:emit=False
        message=f'【{phase}】{status[len(phase)+1:]}'
        if elapsed is not None:message+=' · 已用 '+duration(elapsed)
        if emit:self.previous[phase]=(percent,elapsed or 0,done)
        return {'handled':True,'percent':min(99,percent),'status':status,'log':message if emit else None}

def completion_summary(kind,details):
    label='读取' if kind=='read' else '写入'
    checked=(details.get('verification',{}).get('matched',False) if kind=='read'
             else details.get('verification_performed',details.get('verified',False)))
    if details.get('unchecked_resume_bytes') or details.get('unverified_blocks'):checked=False
    parts=[f'【{label}完成】'+('校验通过' if checked else '未完成数据回读校验')]
    if details.get('duration_seconds') is not None:parts.append('总耗时 '+duration(details['duration_seconds']))
    if kind=='write':
        parts.extend([f"写入 {details.get('programmed_sectors',0):,} 块",f"跳过 {details.get('skipped_sectors',0):,} 块"])
        if details.get('unchecked_resume_bytes'):parts.append('续写前缀未复核')
    return ' · '.join(parts)
