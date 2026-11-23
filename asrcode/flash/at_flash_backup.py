"""Read-only full flash backup via the device's unmodified AT*REGRW handler."""
from pathlib import Path
import hashlib
import json
import re
import struct
import time
import serial
import argparse
import os
from asrcode.flash.asr_io_settings import baudrate_value,read_state_dir,read_paths,migrate_read_state
from asrcode.flash.operation_control import check_stop, OperationCancelled

OUT=Path(__file__).resolve().parent


READ_WORDS_RE = re.compile(
    rb'(?:\*REGRW:\s*(?:0x)?([0-9a-fA-F]+),\s*(?:0x)?([0-9a-fA-F]+)|'
    rb'(?:^|[\r\n])0[xX]([0-9a-fA-F]+):\s*0[xX]([0-9a-fA-F]+))')
TERMINAL_RE = re.compile(
    rb'(?:^|\r\n)(?:OK|ERROR(?::[^\r\n]*)?|\+(?:CME|CMS) ERROR:[^\r\n]*)\r\n')

def parse_read_words(response):
    """ASR firmware families use either a named response or an address:value line."""
    return [(a or c,b or d) for a,b,c,d in READ_WORDS_RE.findall(response)]

def exchange(s, command, timeout=3):
    payload = command.encode('ascii')
    for attempt in range(3):
        try:
            s.write(payload)
            break
        except (PermissionError, OSError):
            if attempt == 2:
                raise
            time.sleep(0.02 * (attempt + 1))
            if hasattr(s, 'reset_output_buffer'):
                try:
                    s.reset_output_buffer()
                except Exception:
                    pass
    response=bytearray()
    end=time.monotonic()+timeout
    import serial
    while time.monotonic()<end:
        try:
            n=s.in_waiting if hasattr(s,'in_waiting') else 0
            chunk=s.read(n if n>0 else 1)
        except (PermissionError, serial.SerialException, OSError):
            time.sleep(0.02)
            continue
        if chunk:
            response.extend(chunk)
            terminal=TERMINAL_RE.search(response)
            if terminal:
                # A URC after the acknowledgement is not part of this transaction.
                return bytes(response[:terminal.end()])
    raise RuntimeError(f'Incomplete AT response: {bytes(response[-240:])!r}')


def read_words(s, address, count):
    if not 1<=count<=80 or address<0 or address%4 or address+count*4>0x100000000:
        raise ValueError('Read must be aligned and contain 1 to 80 words')
    if count>80:
        return b''.join(read_words(s,address+i*4,min(80,count-i)) for i in range(0,count,80))
    commands='AT'+';'.join(f'*REGRW=r,{address+i*4:08x}' for i in range(count))+'\r'
    response=exchange(s,commands)
    words=parse_read_words(response)
    if len(words)!=count or not response.endswith(b'\r\nOK\r\n'):
        raise RuntimeError(f'Invalid batch at {address:#x}: {len(words)}/{count} words')
    # Validate the entire batch before committing any bytes to the output.
    values=[]
    for i,(returned,value) in enumerate(words):
        if int(returned,16)!=address+4*i:
            raise RuntimeError('Out-of-order readback')
        values.append(struct.pack('<I',int(value,16)))
    return b''.join(values)


def read_words_pipeline(s,address,count,words=80):
    """Compatibility grouping only: never send a second AT command before its ACK.

    Live double-read validation found silent value corruption with concurrent
    commands, even when addresses, word count and both OK markers were valid.
    """
    if not 1<=words<=80 or not 1<=count<=words*2:
        raise ValueError('Read grouping must fit two batches of at most 80 words')
    blocks=[]
    for i in range(0,count,words):
        blocks.append(read_words(s,address+i*4,min(words,count-i)))
    return b''.join(blocks)


def synchronize(s):
    # Discard stale fragments before sending a new command; never combine replies.
    s.reset_input_buffer()
    reply=exchange(s,'AT\r')
    if not reply.endswith(b'\r\nOK\r\n') or b'*REGRW:' in reply:
        raise RuntimeError('AT synchronization failed')


def read_addresses(s, addresses):
    """One completed AT transaction; never queue a second request."""
    addresses=list(addresses)
    if not addresses:
        return b''
    if len(addresses)>32:
        return b''.join(read_addresses(s, addresses[i:i+80]) for i in range(0, len(addresses), 80))
    if any(a<0 or a%4 or a>0xfffffffc for a in addresses):
        raise ValueError('Invalid compound read')
    command='AT'+';'.join(f'*REGRW=r,{a:08x}' for a in addresses)+'\r'
    reply=exchange(s,command)
    words=parse_read_words(reply)
    if (not reply.endswith(b'\r\nOK\r\n') or b'ERROR' in reply or len(words)!=len(addresses)
            or any(int(a,16)!=expected for (a,_),expected in zip(words,addresses))):
        raise RuntimeError('Compound read address/count/ACK mismatch')
    return b''.join(struct.pack('<I',int(v,16)) for _,v in words)


def describe_disagreement(address,first,second):
    """Describe actual bytes without guessing which sample is correct."""
    positions=[i for i,(left,right) in enumerate(zip(first,second)) if left!=right]
    result={'differing_bytes':len(positions)+abs(len(first)-len(second)),
            'sample_lengths':[len(first),len(second)],
            'sample_zero_bytes':[value.count(0) for value in (first,second)],
            'sample_cc_bytes':[value.count(0xcc) for value in (first,second)]}
    if positions:
        start=positions[0];end=min(start+16,len(first),len(second))
        result.update(first_difference_address=address+start,
                      difference_sample=[value[start:end].hex() for value in (first,second)])
    return result


class VerifiedReader:
    """Verify each block before commit, with automatic conservative fallback."""
    def __init__(self,port,stop_file=None,verify=True,mismatch_handler=None):
        self.port=port
        self.stop_file=stop_file
        self.verify=verify
        self.mismatch_handler=mismatch_handler
        self.unverified_blocks=[]
        self.stats={'retry_count':0,'disagreements':0,'commands':0,'verified_bytes':0}

    def _read(self,address,length,words):
        if getattr(self,'native',None) is not None:
            data=self.native.read(address,length)
            self.stats['commands']+=1
            return data
        return self._mapped_read(address,length,words)

    def _mapped_read(self,address,length,words=32):
        data=bytearray()
        while len(data)<length:
            check_stop(self.stop_file)
            count=min(words,getattr(self,'max_compound_words',32),(length-len(data))//4)
            for attempt in range(3):
                check_stop(self.stop_file)
                try:
                    self.stats['commands']+=1
                    block=read_addresses(self.port,(address+len(data)+i*4 for i in range(count)))
                    break
                except (RuntimeError,OSError,serial.SerialException) as exc:
                    if attempt==2:raise
                    self.stats['retry_count']+=1
                    count=min(count,16 if attempt==0 else 4)
                    self.max_compound_words=count
                    print(f'READ_TRANSPORT_RETRY address={address+len(data):#x} words={count} reason={exc}',flush=True)
                    # Wait for outstanding device output to finish before a new AT.
                    until=time.monotonic()+2;quiet=time.monotonic()
                    while time.monotonic()<until:
                        check_stop(self.stop_file)
                        if self.port.read(max(1,self.port.in_waiting)):quiet=time.monotonic()
                        elif time.monotonic()-quiet>=.1:break
                        time.sleep(.005)
                    synchronize(self.port)
            data.extend(block)
        return bytes(data)

    def read_block(self,address,length):
        if address<0 or address%4 or not 0<length<=4096 or length%4 or address+length>0x100000000:
            raise ValueError('Invalid verified block')
        if not self.verify:
            return self._read(address,length,48)
        last=None
        native=getattr(self,'native',None)
        pairs=((32,32),(16,16),(8,8)) if hasattr(native,'mapped_only') else ((80,80),(64,64),(32,32))
        for attempt,(first_words,second_words) in enumerate(pairs):
            if attempt==1 and hasattr(native,'conservative'):native.conservative(address)
            if attempt==2 and hasattr(native,'mapped_only'):native.mapped_only(address)
            check_stop(self.stop_file)
            first=self._read(address,length,first_words)
            second=self._read(address,length,second_words)
            if first==second:
                self.stats['verified_bytes']+=length
                return first
            self.stats['disagreements']+=1
            self.stats['retry_count']+=1
            last={'address':address,'length':length,'attempts':attempt+1,
                  'hashes':[hashlib.sha256(value).hexdigest() for value in (first,second)]}
            last.update(describe_disagreement(address,first,second))
            print('READ_DISAGREEMENT '+json.dumps(last),flush=True)
            if attempt<len(pairs)-1:
                print(f'READ_RETRY {address:#x} attempt={attempt+1}/{len(pairs)}; pair discarded',flush=True)
                synchronize(self.port)
        if self.mismatch_handler and self.mismatch_handler(last)=='continue':
            # Retain the last sample to preserve all subsequent offsets. It is
            # explicitly untrusted, and the output cannot become a flash input.
            self.unverified_blocks.append(last)
            return second
        raise OperationCancelled('Persistent read mismatch; user stopped')


def console_mismatch(info):
    print('READ_MISMATCH '+json.dumps(info),flush=True)
    try:answer=input().strip()
    except EOFError:return 'stop'
    return 'continue' if answer=='continue' else 'stop'


def verify_file_on_device(port, expected, base, stop_file=None, pipeline_depth=1,baudrate=115200):
    received=0
    retries=0
    depth=pipeline_depth
    stable=0
    pipeline_faults=0
    failures=0
    next_report=0
    started=time.monotonic()
    s=None
    digest=hashlib.sha256()
    try:
        while received<len(expected):
            check_stop(stop_file)
            count=min(80*depth,(len(expected)-received)//4)
            try:
                if s is None:
                    s=serial.Serial(port,baudrate_value(baudrate),timeout=.001,write_timeout=3)
                    synchronize(s)
                block=(read_words_pipeline(s,base+received,count) if depth==2 else read_words(s,base+received,count))
            except (OSError,RuntimeError,serial.SerialException):
                retries+=1;failures+=1;stable=0
                if depth==2:pipeline_faults+=1
                depth=1
                if s is not None:s.close();s=None
                if failures>=12:raise RuntimeError('Verification connection failed repeatedly')
                time.sleep(.2)
                continue
            if block!=expected[received:received+len(block)]:
                different=next(i for i,(a,b) in enumerate(zip(block,expected[received:])) if a!=b)
                raise RuntimeError(f'Two reads differ at Flash offset {received+different:#x}; not marked complete')
            received+=len(block);digest.update(block);failures=0;stable+=1
            if depth==1 and pipeline_depth==2 and stable>=256 and pipeline_faults<3:
                depth=2;stable=0
            if received>=next_report or received==len(expected):
                print(f'READ_VERIFY {received:#x}/{len(expected):#x}',flush=True)
                next_report=received+0x10000
    finally:
        if s is not None:s.close()
    return {'matched':True,'sha256':digest.hexdigest(),'bytes':received,'retry_count':retries,
            'seconds':time.monotonic()-started}


def read_exact(reader,address,length):
    """Read verified aligned words, returning exactly the requested bytes."""
    if length<=0 or address<0 or address+length>0x100000000:
        raise ValueError('Invalid read range')
    first=address//4*4;end=(address+length+3)//4*4
    data=bytearray()
    for start in range(first,end,4096):
        data.extend(reader.read_block(start,min(4096,end-start)))
    return bytes(data[address-first:address-first+length])


def read_device_partitions(reader,image_size=0x2000000):
    """Discover TIM using only verified memory reads; never write registers."""
    from asrcode.flash.qspi_flash_writer import tim_partitions
    header=read_exact(reader,0x80000000,56)
    count=struct.unpack_from('<I',header,44)[0]
    if header[4:8]!=b'HMIT' or not 1<=count<=64:
        raise ValueError('Invalid device TIM header')
    table=read_exact(reader,0x80000000,56+count*96)
    if table[:56]!=header:
        raise ValueError('Device TIM header changed during discovery')
    return tim_partitions(table,image_size=image_size)


def _detect_flash_read_profile(port,stop_file=None):
    """Verify mapped TIM and its repetition period without changing QSPI registers.

    The period measures the readable mapping, not an independently queried JEDEC ID.
    Unknown periods still allow declared TIM partitions to be read.
    """
    reader=VerifiedReader(port,stop_file)
    rows=read_device_partitions(reader,image_size=0x2000000)
    offsets=[0]
    samples=[read_exact(reader,0x80000000,64)]
    for row in rows:
        if row['offset'] in offsets or row['size']<64:continue
        sample=read_exact(reader,0x80000000+row['offset'],64)
        if len(set(sample))<8 or sample in samples:continue
        offsets.append(row['offset']);samples.append(sample)
        if len(offsets)>=3:break
    # Some valid boot TIMs contain only TIMH and OBMI. Sample inside declared
    # images as well, rather than treating the number of entries as capacity.
    for row in rows:
        if len(samples)>=3:break
        for delta in (0x100, row['size']//2//4*4):
            offset=row['offset']+delta
            if delta<0 or delta+64>row['size'] or offset in offsets:continue
            sample=read_exact(reader,0x80000000+offset,64)
            if len(set(sample))<8 or sample in samples:continue
            offsets.append(offset);samples.append(sample)
            if len(samples)>=3:break
    enough=len(samples)>=3 and len(set(samples))==len(samples) and all(len(set(block))>2 for block in samples)
    lower_bound=max(row['offset']+row['size'] for row in rows)
    period=0;checks=[]
    candidate=0x100000
    while candidate<lower_bound:candidate*=2
    if enough:
        while candidate<=0x2000000:
            matched=True
            for multiplier in (1,2):
                for offset,expected in zip(offsets,samples):
                    actual=read_exact(reader,0x80000000+candidate*multiplier+offset,64)
                    same=actual==expected
                    checks.append({'period':candidate,'multiplier':multiplier,'offset':offset,'matched':same})
                    if not same:
                        matched=False;break
                if not matched:break
            if matched:
                period=candidate;break
            candidate*=2
    return {'read_supported':True,'flash_base':0x80000000,'flash_size':period,
            'partitions':rows,'header':samples[0][:8].hex(),
            'size_source':'TIM 表与三点双周期映射回卷验证' if period else '仅确认 TIM 声明范围，整机长度未确认',
            'jedec_verified':False,'capacity_checks':checks}


def detect_flash_read_profile(port,stop_file=None):
    for attempt in range(3):
        check_stop(stop_file)
        try:
            profile=_detect_flash_read_profile(port,stop_file)
            if profile['flash_size'] or attempt==2:return profile
        except OperationCancelled:
            raise
        except (ValueError,RuntimeError,OSError):
            if attempt==2:raise
        synchronize(port)
    raise RuntimeError('Unable to classify Flash mapping')


def validate_read_partition(port,name,base,length,stop_file=None,connection=None,baudrate=115200):
    if connection is None:
        with serial.Serial(port,baudrate_value(baudrate),timeout=.001,write_timeout=3) as wire:
            synchronize(wire)
            rows=read_device_partitions(VerifiedReader(wire,stop_file))
    else:
        rows=read_device_partitions(VerifiedReader(connection,stop_file))
    row=next((r for r in rows if r['name']==name),None)
    if row is None or (base,length)!=(0x80000000+row['offset'],row['size']):
        raise ValueError('Device TIM partition missing or layout changed: '+name+'; probe device again')
    return row


def _read_main(port='COM10', destination=None, length=8388608, base=0x80000000,
         batch_words=None, fresh=False, stop_file=None, pipeline_depth=None, verify_pass=None, partition=None, reread_verify=True, mismatch_handler=None,overwrite=False,_connection=None,baudrate=115200,state_dir=None,records_dir=None):
    """Fixed single-owner, verified-block read. Legacy tuning arguments are ignored."""
    if length<=0 or base<0 or base+length>0x100000000:
        raise ValueError('Invalid Flash range')
    baudrate=baudrate_value(baudrate)
    selected=validate_read_partition(port,partition,base,length,stop_file,connection=_connection,baudrate=baudrate) if partition else None
    destination=Path(destination) if destination else OUT/'device_flash_verified_read.work.bin'
    paths=read_paths(destination,state_dir)
    if state_dir is not None:Path(state_dir).mkdir(parents=True,exist_ok=True)
    if fresh and destination.exists():
        if not overwrite:
            raise ValueError('New backup requires a new output file; existing file preserved')
        check_stop(stop_file)
        stamp=str(time.time_ns())
        for existing in dict.fromkeys([destination]+list(paths.values())+list(read_paths(destination).values())):
            if existing.exists():
                folder=Path(records_dir)/'覆盖前备份' if records_dir is not None else existing.parent
                folder.mkdir(parents=True,exist_ok=True)
                tag=hashlib.sha256(str(existing.resolve()).encode('utf-8')).hexdigest()[:8] if records_dir is not None else ''
                saved=folder/(existing.name+'.before_overwrite_'+stamp+tag+'.work')
                existing.replace(saved)
                print('覆盖前保留旧文件：'+str(saved),flush=True)
    destination.parent.mkdir(parents=True,exist_ok=True)
    if state_dir is not None and destination.exists():paths=migrate_read_state(destination,state_dir)
    resume_meta=paths['resume']
    checkpoint=paths['checkpoint']
    result_path=paths['result']
    expected={'port':port,'length':length,'base_address':hex(base)}
    if partition:expected['partition']=partition
    start=destination.stat().st_size if destination.exists() else 0
    if (start%4 and not checkpoint.exists()) or start>length:
        raise ValueError('Invalid resume size')
    if start:
        saved_meta=json.loads(resume_meta.read_text(encoding='utf-8')) if resume_meta.exists() else None
        legacy_expected={key:value for key,value in expected.items() if key!='partition'}
        if saved_meta!=expected and not (partition and saved_meta==legacy_expected):
            raise ValueError('Resume parameters do not match the existing partial backup')
    else:
        resume_meta.write_text(json.dumps(expected,indent=2),encoding='utf-8')
    digest=hashlib.sha256()
    unverified=[]
    prefix_verified=True
    began=time.monotonic();serial_port=None;reader=None;offset=0;acceleration=None;cellular=None
    result={'complete':False,'file':str(destination),'port':port,'base_address':hex(base),
            'size':start,'requested_size':length,'resumed_from':start,'writes_executed':False,
            'method':'serialized compound AT with verified 4KiB blocks',
            'max_pending_commands':1,'max_words_per_command':80,'host_baudrate':baudrate,'reread_verify':reread_verify}
    if selected:result['partition']=selected
    def save():
        temp=result_path.with_suffix('.json.tmp')
        temp.write_text(json.dumps(result,indent=2),encoding='utf-8');temp.replace(result_path)
    def commit_checkpoint():
        temp=checkpoint.with_suffix('.json.tmp')
        temp.write_text(json.dumps({'size':offset,'sha256':digest.hexdigest(),'unverified_blocks':unverified+getattr(reader,'unverified_blocks',[]),'all_blocks_verified':bool(reread_verify and prefix_verified and not unverified and not getattr(reader,'unverified_blocks',[]))}),encoding='utf-8');temp.replace(checkpoint)
    save()
    try:
        check_stop(stop_file)
        if checkpoint.exists() and start:
            saved=json.loads(checkpoint.read_text(encoding='utf-8'));size=saved.get('size')
            unverified=list(saved.get('unverified_blocks',[]))
            prefix_verified=saved.get('all_blocks_verified',True)
            if not isinstance(size,int) or (size%4 and size!=length) or not 0<=size<=start:
                raise ValueError('Invalid partial backup checkpoint')
            check=hashlib.sha256()
            with destination.open('rb') as stream:
                remaining=size
                while remaining:
                    data=stream.read(min(1048576,remaining));check.update(data);remaining-=len(data)
            if check.hexdigest()!=saved['sha256']:
                raise ValueError('Partial backup checksum mismatch')
            if size<start:
                # A crash can leave an uncommitted tail, including a short word.
                # Only the hash-verified checkpoint is eligible for continuation.
                with destination.open('rb+') as stream:stream.truncate(size)
                start=size
                result.update(size=start,resumed_from=start)
                print(f'续读：丢弃未提交尾部，从已校验断点 {start:#x} 继续',flush=True)
        serial_port=_connection if _connection is not None else serial.Serial(port,baudrate_value(baudrate),timeout=.001,write_timeout=3)
        if _connection is None:synchronize(serial_port)
        from asrcode.flash.asr_flash_session import CellularSession
        cellular=CellularSession(serial_port)
        cellular.start()
        result['cellular_session']=cellular.events
        reader=VerifiedReader(serial_port,stop_file)
        if not reread_verify or mismatch_handler:
            reader=VerifiedReader(serial_port,stop_file,verify=reread_verify,mismatch_handler=mismatch_handler)
        from asrcode.flash.at_read_acceleration import ReadAcceleration
        acceleration=ReadAcceleration(serial_port,base,length,stop_file)
        acceleration.start()
        from asrcode.flash.asr_read_recovery import RecoveringBinaryReader
        reader.native=(RecoveringBinaryReader(acceleration.native,lambda:synchronize(serial_port),
                      reader._mapped_read,lambda:check_stop(stop_file),reader.stats,
                      lambda line:print(line,flush=True)) if acceleration.native else None)
        result.update(read_transport='READFLASH binary' if acceleration.native else 'REGRW text',
                      echo_disabled=acceleration.echo_disabled,
                      acceleration_probe_error=acceleration.probe_error)
        if acceleration.native:
            result['method']='serialized binary AT*READFLASH with 4KiB commits'
            result['max_binary_bytes_per_command']=4096
        print('READ_TRANSPORT '+json.dumps({'transport':result['read_transport'],
              'echo_disabled':acceleration.echo_disabled,'probe_error':acceleration.probe_error}),flush=True)
        # Hash the committed local prefix; only probe its boundaries on device.
        # Re-reading the complete prefix defeats actual checkpoint resumption.
        if start:
            with destination.open('rb') as stream:
                while offset<start:
                    size=min(1048576,start-offset);disk=stream.read(size)
                    digest.update(disk);offset+=size
                for edge in sorted({0,max(0,start-4096)}):
                    size=min(4096,start-edge);stream.seek(edge)
                    if read_exact(reader,base+edge,size)!=stream.read(size):
                        raise ValueError(f'Resume data differs from device at boundary {edge:#x}; existing file preserved')
            print('RESUME_CHECK verified',flush=True)
        began=time.monotonic()
        print(f'RESUME {start:#x}',flush=True)
        next_report=start
        with destination.open('ab') as stream:
            while offset<length:
                data=read_exact(reader,base+offset,min(4096,length-offset))
                stream.write(data);digest.update(data);offset+=len(data)
                if offset>=next_report or offset==length:
                    stream.flush();os.fsync(stream.fileno());commit_checkpoint()
                    result['size']=offset;result['reader']=dict(reader.stats);save()
                    print(f'READ {offset:#x}/{length:#x} elapsed={time.monotonic()-began:.1f}s',flush=True)
                    next_report=offset+65536
            stream.flush();os.fsync(stream.fileno());commit_checkpoint()
        actual=hashlib.sha256()
        with destination.open('rb') as stream:
            for block in iter(lambda:stream.read(1048576),b''):actual.update(block)
        if destination.stat().st_size!=length or actual.hexdigest()!=digest.hexdigest():
            raise RuntimeError('Final file length or disk checksum mismatch')
        all_unverified=unverified+getattr(reader,'unverified_blocks',[])
        result.update(complete=not all_unverified,finished=True,size=length,sha256=actual.hexdigest(),unverified_blocks=all_unverified,
                      prefix_verified=prefix_verified,
                      verification={'matched':bool(reread_verify and prefix_verified and not all_unverified),'mode':'repeated blocks' if reread_verify else 'single pass','bytes':length},
                      bytes_read_this_run=length-start,duration_seconds=time.monotonic()-began,
                      reader=dict(reader.stats),retry_count=reader.stats['retry_count'])
        result['kib_per_second']=(length-start)/1024/max(.001,result['duration_seconds'])
        save()
    except Exception as exc:
        # Only already verified blocks have entered the output; never mark a
        # failed/short/changed block complete, including a canceled resume check.
        result.update(complete=False,error=repr(exc),cancelled=isinstance(exc,OperationCancelled),
                      size=destination.stat().st_size if destination.exists() else 0,
                      duration_seconds=time.monotonic()-began)
        if reader is not None:result['reader']=dict(reader.stats)
        if offset and destination.exists() and offset==destination.stat().st_size:
            with destination.open('rb+') as stream:stream.flush();os.fsync(stream.fileno())
            commit_checkpoint()
        save();raise
    finally:
        try:
            if acceleration is not None:acceleration.close()
        finally:
            try:
                if cellular is not None:cellular.close()
            except Exception as exc:
                result.update(complete=False,error='蜂窝状态恢复失败：'+str(exc));save();raise
            finally:
                if cellular is not None:
                    result['cellular_session']=cellular.events;save()
                if serial_port is not None and _connection is None:serial_port.close()
    print('COMPLETE',json.dumps(result),flush=True)
    return result


def main(port='COM10',destination=None,length=8388608,base=0x80000000,
         batch_words=None,fresh=False,stop_file=None,pipeline_depth=None,verify_pass=None,
         partition=None,reread_verify=True,mismatch_handler=None,overwrite=False,baudrate=115200,state_dir=None,records_dir=None):
    """One serial owner for TIM preflight, transfer, verification and resume."""
    options=dict(port=port,destination=destination,length=length,base=base,batch_words=batch_words,
                 fresh=fresh,stop_file=stop_file,pipeline_depth=pipeline_depth,verify_pass=verify_pass,
                 partition=partition,reread_verify=reread_verify,mismatch_handler=mismatch_handler,
                 overwrite=overwrite,baudrate=baudrate_value(baudrate),state_dir=state_dir,records_dir=records_dir)
    if length<=0 or base<0 or base+length>0x100000000:raise ValueError('Invalid Flash range')
    if partition:
        with serial.Serial(port,baudrate_value(baudrate),timeout=.001,write_timeout=3) as wire:
            synchronize(wire)
            return _read_main(**options,_connection=wire)
    return _read_main(**options)


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    from asrcode.flash.cli_options import add_boolean_option
    ap.add_argument('--port',default='COM10')
    ap.add_argument('--baudrate',type=int,default=115200)
    ap.add_argument('--state-dir',type=Path)
    ap.add_argument('--records-dir',type=Path)
    ap.add_argument('--output',type=Path,default=OUT/'device_flash_verified_read.work.bin')
    ap.add_argument('--length',type=lambda x:int(x,0),default=8388608)
    ap.add_argument('--base',type=lambda x:int(x,0),default=0x80000000)
    ap.add_argument('--partition',help='TIM name; validate selected base and length against the device before reading')
    ap.add_argument('--fresh',action='store_true')
    ap.add_argument('--overwrite',action='store_true')
    add_boolean_option(ap,'--reread-verify',default=True)
    ap.add_argument('--stop-file',type=Path)
    # Accept old saved launch commands without exposing obsolete modes.
    ap.add_argument('--batch-words',help=argparse.SUPPRESS)
    ap.add_argument('--pipeline-depth',help=argparse.SUPPRESS)
    ap.add_argument('--verify-pass',action='store_true',help=argparse.SUPPRESS)
    ap.add_argument('--no-verify-pass',action='store_true',help=argparse.SUPPRESS)
    args=ap.parse_args()
    try:
        main(args.port,args.output,args.length,args.base,fresh=args.fresh,stop_file=args.stop_file,partition=args.partition,reread_verify=args.reread_verify,mismatch_handler=console_mismatch,overwrite=args.overwrite,baudrate=args.baudrate,state_dir=args.state_dir or read_state_dir(args.output),records_dir=args.records_dir or read_state_dir(args.output)/"过程文件")
    except OperationCancelled:
        print('CANCELLED read; verified partial file preserved',flush=True)
        raise SystemExit(2)
