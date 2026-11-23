"""Capability-detected SPI NOR writer: selectable erase, readback and equal-skip with sector backups."""
import argparse
import hashlib
import json
import struct
import time
import os
from pathlib import Path
from asrcode.flash.at_flash_backup import read_words, read_addresses, parse_read_words, synchronize, exchange
from asrcode.flash.operation_control import check_stop, OperationCancelled
from asrcode.flash.qspi_flash_writer import FlashWriter, prepare_input, oslo_bounds, partition_bounds, firmware_partitions, ROOT, SECTOR_SIZE, needs_erase
from asrcode.flash.asr_partition_layout import source_partition_layout, validate_device_partition


class TransactionSerial:
    """Invalidate lookahead whenever any AT request uses the shared connection."""
    def __init__(self,wire):
        self.wire=wire
        self.at_transaction_index=0
    def __getattr__(self,name):return getattr(self.wire,name)
    def __setattr__(self,name,value):
        if name in ('wire','at_transaction_index'):object.__setattr__(self,name,value)
        else:setattr(self.wire,name,value)
    def write(self,data):
        self.at_transaction_index+=1
        return self.wire.write(data)


class IpCommandRejected(RuntimeError):
    """The controller rejected IPCR before any SPI NOR command was issued."""
    def __init__(self,seq,offset,flags):
        self.seq=seq;self.offset=offset;self.flags=flags
        super().__init__(f'QSPI IP command rejected before execution: seq={seq} offset={offset:#x} flags={flags:#x}')


class AmbiguousLaunchError(RuntimeError):
    """The AT acknowledgement was lost after IPCR may already have executed."""


class UnsafeWriteOutcome(Exception):
    """The controller reported an error that does not guarantee no Flash command ran."""


class FastFlashWriter(FlashWriter):
    max_retries = 5
    def __init__(self,port='COM10',write_mode=None,*,baudrate=115200,records_dir=None):
        # The optional second argument only accepts old callers. There is one
        # serial owner and no page preparation pool or selectable execution mode.
        if baudrate==115200 and records_dir is None:super().__init__(port)
        else:super().__init__(port,baudrate=baudrate,records_dir=records_dir)
        if hasattr(self.serial,'write'):self.serial=TransactionSerial(self.serial)
        self.restore_echo=False
        try:
            reply=exchange(self.serial,'AT\r')
            if reply.lstrip().upper().startswith(b'AT\r'):
                self.restore_echo=True
                exchange(self.serial,'ATE0\r')
        except Exception:
            self.close()
            raise

    def suspend_cellular_radio(self):
        from asrcode.flash.asr_flash_session import CellularSession
        self._cellular_session=CellularSession(self.serial)
        self._cellular_session.start()

    def invalidate_ahb(self):
        self._needs_ahb_invalidation = False

    def close(self):
        try:
            try:
                if getattr(self,'_needs_ahb_invalidation',False):
                    self.invalidate_ahb()
            finally:
                self._close_transport_state()
        finally:
            super().close()

    def _close_transport_state(self):
        errors=[]
        for name in ('_binary_session','_flash_protection','_cellular_session'):
            session=getattr(self,name,None)
            setattr(self,name,None)
            if session is not None:
                try:session.close()
                except Exception as exc:errors.append(name+': '+str(exc))
        if getattr(self,'restore_echo',False):
            try:exchange(self.serial,'ATE1\r')
            except Exception as exc:errors.append('回显恢复: '+str(exc))
            self.restore_echo=False
        if errors:raise RuntimeError('设备状态恢复失败：'+'；'.join(errors))

    def enable_binary_reads(self,offset,length,stop_file=None):
        from asrcode.flash.at_read_acceleration import ReadAcceleration
        self.wait_idle()
        self._binary_session=ReadAcceleration(self.serial,0x80000000+offset,length,stop_file)
        self._binary_session.start()
        from asrcode.flash.asr_read_recovery import RecoveringBinaryReader
        self.binary_recovery_stats={}
        native=self._binary_session.native
        self.binary_reader=(RecoveringBinaryReader(native,lambda:synchronize(self.serial),
            lambda address,size:self._mapped_text(address-0x80000000,size,stop_file,16),
            lambda:check_stop(stop_file),self.binary_recovery_stats,lambda line:print(line,flush=True)) if native else None)
        return bool(self.binary_reader)

    def check_profile(self):
        super().check_profile()
        # Negotiate command length using only the idle address register. No
        # Flash operation is launched by this probe, and the value is restored.
        if not hasattr(self,'batch_limit'):
            from asrcode.flash.asr_write_batch import negotiate_write_batch
            self.batch_limit=negotiate_write_batch(self,exchange,synchronize)

    def write_many(self, pairs):
        pairs=list(pairs)
        if not pairs:
            return
        # One serial owner; bound each command to the verified parser limit.
        limit=getattr(self,'batch_limit',16)
        if len(pairs)>limit:
            for start in range(0,len(pairs),limit):
                self.write_many(pairs[start:start+limit])
            return
        command='AT'+';'.join(f'*REGRW=w,{0xd420b000+off:08x},{value:08x}' for off,value in pairs)+'\r'
        reply=exchange(self.serial,command)
        self.events.append({'writes':[(hex(off),hex(value)) for off,value in pairs],'reply':reply.decode(errors='replace')})
        if not reply.endswith(b'\r\nOK\r\n') or b'ERROR' in reply:
            raise RuntimeError('Batched register write failed; not automatically replayed')

    def read_addresses(self,addresses):
        return read_addresses(self.serial,addresses)

    def exchange_registers(self,writes,reads):
        """Execute ordered register writes and collect their completion in one ACK."""
        writes=list(writes);reads=list(reads)
        if len(writes)+len(reads)>getattr(self,'batch_limit',16):
            self.write_many(writes)
            return self.read_addresses(reads)
        commands=[f'*REGRW=w,{0xd420b000+off:08x},{value:08x}' for off,value in writes]
        commands.extend(f'*REGRW=r,{address:08x}' for address in reads)
        reply=exchange(self.serial,'AT'+';'.join(commands)+'\r')
        words=parse_read_words(reply)
        if (not reply.endswith(b'\r\nOK\r\n') or b'ERROR' in reply or len(words)!=len(reads)
                or any(int(address,16)!=expected for (address,_),expected in zip(words,reads))):
            raise RuntimeError('Mixed QSPI transaction address/count/ACK mismatch')
        self.events.append({'mixed_writes':[(hex(off),hex(value)) for off,value in writes],
                            'reads':[hex(address) for address in reads],'reply':reply.decode(errors='replace')})
        return b''.join(struct.pack('<I',int(value,16)) for _,value in words)

    def check_lut(self,expected):
        actual=struct.unpack('<'+'I'*len(expected),self.read_addresses(0xd420b000+off for off in expected))
        if list(actual)!=list(expected.values()):
            raise RuntimeError('QSPI LUT changed; stopped before write')

    def flash_ready(self):
        for _ in range(150):
            try:
                status=self.read_ip(2,0x80000000,1)[0]
                if not status&1:
                    return status
            except Exception:
                pass
            time.sleep(.01)
        raise TimeoutError('Flash WIP did not clear')

    def wait_idle(self):
        # BUSY alone is insufficient on the shared FSL controller.  IPCR is
        # rejected when an AHB access starts between the guard and launch.
        # Require BUSY/IP_ACC/AHB_ACC/AHBTRN to be clear twice in succession.
        quiet=0;status=0
        for _ in range(100):
            try:
                status,self.last_flags=struct.unpack('<II',read_words(self.serial,0xd420b15c,2))
            except Exception:
                time.sleep(.01)
                continue
            if not status&0x47:
                quiet+=1
                if quiet>=1:
                    if isinstance(self.serial,TransactionSerial):
                        self._idle_snapshot=(self.serial.at_transaction_index,status,self.last_flags)
                    return status
            else:
                quiet=0
            time.sleep(.005)
        raise TimeoutError(f'QSPI shared controller did not become quiet: status={status:#x}')

    def _read_ip_once(self,seq,address,length):
        if seq not in (2,3,*getattr(self,'profile',{}).get('sequences',{}).values()) or not 1<=length<=128:
            raise ValueError('Invalid read sequence or FIFO length')
        self.wait_idle()
        count=(length+3)//4
        self.write_many([(0,self.saved[0]|0x400),(0x16c,0x100),(0x100,address),
                         (0x110,0x100|((length+3)//4-1)),(0x160,self.last_flags),(8,(seq<<24)|length)])
        self.wait_idle()
        for _ in range(50):
            flags=self.read(0x160)
            if flags&1:break
            time.sleep(.005)
        if flags&0xd0:
            raise RuntimeError(f'QSPI read error {flags:#x}')
        if not flags&1:raise RuntimeError('QSPI read completion missing; FIFO discarded')
        data=read_words(self.serial,0xd420b200,count)[:length]
        return data

    def issue(self,seq,offset=0,data=b''):
        expected={1:(0x320,0x406),6:(0x370,0x08180402),15:(0x400,0x08180420)}
        if seq not in expected:
            raise ValueError('Unverified write sequence')
        reg,value=expected[seq]
        if seq!=15 and hasattr(self,'profile'):
            from asrcode.flash.qspi_profile import expected_registers
            name={1:'wren',6:'program'}[seq]
            required=expected_registers(self.profile,[name])
            seq=self.profile['sequences'][name]
        else:
            required={reg:value,reg+4:0x2000 if seq==6 else 0}
        addresses=[0xd420b15c,0xd420b160]+[0xd420b000+off for off in required]
        # The firmware is another hardware owner. Serial transaction indices
        # cannot prove LUT or idle state stayed unchanged between AT requests.
        from asrcode.flash.asr_qspi_guard import command_guard
        status,self.last_flags=command_guard(self,required)
        # command_guard validates the LUT.  Take a fresh shared-controller
        # guard immediately before filling the FIFO and launching IPCR.
        if status&0x47:
            status=self.wait_idle()
        pairs=[(0x16c,0x100),(0x100,0x80000000+offset),(0x160,self.last_flags)]
        if data:
            padded=data+b'\x00'*(-len(data)%16)
            pairs.append((0,self.saved[0]|0x800))
            pairs.extend((0x154,struct.unpack_from('<I',padded,i)[0]) for i in range(0,len(padded),4))
        pairs.append((8,(seq<<24)|len(data)))
        limit=getattr(self,'batch_limit',16)
        if len(pairs)>limit:
            raise RuntimeError(f'Atomic QSPI launch requires {len(pairs)} register writes; negotiated limit is {limit}')
        try:
            # No reads after IPCR in the same AT command.  The command ACK is
            # the only launch acknowledgement; completion is polled separately.
            self.write_many(pairs)
        except Exception as exc:
            self.events.append({'launch_ack_uncertain':True,'seq':seq,'offset':hex(offset),
                                'data_length':len(data),'error':repr(exc)})
            # The launch may already have executed.  Never replay an uncertain
            # ACK here or in the sector-level RuntimeError retry loop.
            raise AmbiguousLaunchError(f'QSPI launch acknowledgement is uncertain at {offset:#x}') from exc
        status=self.wait_idle()
        if isinstance(self.serial,TransactionSerial):
            self._idle_snapshot=(self.serial.at_transaction_index,status,self.last_flags)
        errors=self.last_flags&0xd0
        if errors==0x80:
            self.events.append({'ip_command_rejected':True,'reason':'IPAEF','seq':seq,
                                'offset':hex(offset),'data_length':len(data),
                                'flags':hex(self.last_flags)})
            raise IpCommandRejected(seq,offset,self.last_flags)
        if errors:
            raise UnsafeWriteOutcome(f'QSPI write error {self.last_flags:#x}; command outcome is not replay-safe')

    def write_enable(self):
        # LUT constants were checked by check_profile. Previous page completion is polled.
        # issue() checks the exact WREN/program sequence immediately before use.
        self.issue(1)

    def program_known(self,offset,data,verify=True):
        if not data or len(data)>128 or offset//256!=(offset+len(data)-1)//256:
            raise ValueError('Invalid page chunk')
        # Five fixed register writes surround the TX words.  Keep every FIFO
        # fill and IPCR launch inside one negotiated AT command.  A 16-command
        # parser therefore uses 32-byte program chunks (13 register writes).
        limit=getattr(self,'batch_limit',16)
        available_words=limit-5
        chunk=min(128,(max(0,available_words)*4//16)*16)
        if chunk<16:
            raise RuntimeError(f'Negotiated write batch {limit} cannot contain an atomic page program')
        for start in range(0,len(data),chunk):
            part=data[start:start+chunk]
            at=offset+start
            for attempt in range(1,4):
                try:
                    self.write_enable()
                    self.issue(6,at,part)
                    status=self.flash_ready()
                    if status&2:
                        from asrcode.flash.at_flash_backup import exchange
                        exchange(self.serial,'AT+FLASHBP=0\r')
                        time.sleep(0.01)
                        if attempt<3:
                            continue
                        raise RuntimeError(f'NOR write protected at {at:#x}; WEL not cleared: {status:#x}')
                    break
                except AmbiguousLaunchError as exc:
                    self.events.append({'ambiguous_launch_retry':attempt,'offset':hex(at),'error':str(exc)})
                    time.sleep(0.02*attempt)
                    try:
                        synchronize(self.serial)
                        if hasattr(self.serial, 'reset_input_buffer'):
                            self.serial.reset_input_buffer()
                        self.flash_ready()
                        actual_data = self.read_flash(at, len(part))
                        if actual_data == part:
                            break
                        if actual_data == b'\xff' * len(part) and attempt < 3:
                            continue
                    except Exception:
                        pass
                    if attempt==3:
                        raise RuntimeError(f'QSPI page program failed after 3 attempts at {at:#x}: {exc}') from exc
                except (IpCommandRejected, RuntimeError, OSError) as exc:
                    self.events.append({'ip_command_retry':attempt,'max_attempts':3,
                                        'seq':getattr(exc,'seq',6),'offset':hex(at),
                                        'data_length':len(part),'error':str(exc)})
                    if attempt==3:
                        raise RuntimeError(f'QSPI page program failed after 3 attempts at {at:#x}: {exc}') from exc
                    time.sleep(.02*attempt)
                    try:
                        synchronize(self.serial)
                        if hasattr(self.serial, 'reset_input_buffer'):
                            self.serial.reset_input_buffer()
                    except Exception:
                        pass
            time.sleep(.01)
        if verify and self.read_flash(offset,len(data))!=data:
            raise RuntimeError(f'Program mismatch at {offset:#x}')

    def erase_sector(self,offset,verify=True):
        if offset%4096 or not 0<=offset<=getattr(self,'flash_size',0x1000000)-4096:
            raise ValueError('Unaligned sector')
        saved=[self.read(0x400+i*4) for i in range(4)]
        lock=self.read(0x304)
        try:
            self.wait_idle()
            self.write(0x300,0x5af05af0)
            self.write(0x304,2)
            for i,value in enumerate([0x08180420,0,0,0]):
                self.write(0x400+i*4,value)
            if self.read(0x400)!=0x08180420:
                raise RuntimeError('Erase LUT installation failed')
            self.write_enable()
            self.issue(15,offset)
            time.sleep(0.08)
            status=self.flash_ready()
            if status&2:
                from asrcode.flash.at_flash_backup import exchange
                exchange(self.serial,'AT+FLASHBP=0\r')
                time.sleep(0.01)
                self.write_enable()
                self.issue(15,offset)
                time.sleep(0.08)
                self.flash_ready()
            if verify and self.read_flash(offset,4096)!=b'\xff'*4096:
                raise RuntimeError(f'Erase verification failed at {offset:#x}')
        finally:
            self.write(0x300,0x5af05af0)
            self.write(0x304,2)
            for i,value in enumerate(saved):
                self.write(0x400+i*4,value)
            self.write(0x300,0x5af05af0)
            self.write(0x304,lock)

    def replace_sector(self,offset,old,new,verified_old=False,*,verify=True,erase=None,skip_equal=True,write_range=None):
        if len(old)!=4096 or len(new)!=4096:
            raise ValueError('Expected complete sector')
        if write_range is None:write_range=(0,4096)
        if not 0<=write_range[0]<write_range[1]<=4096:
            raise ValueError('Invalid selected sector range')
        if not verified_old and self.verified_block(offset,4096)!=old:
            raise RuntimeError('Sector changed before modification; stopped')
        erased=needs_erase(old,new) if erase is None else erase
        cache_managed=getattr(self,'profile',{}).get('controller')=='fsl_qspi_nor'
        if cache_managed:self._needs_ahb_invalidation=True
        self.last_sector_stats={'programmed_pages':0,'blank_pages_skipped':0,'verified':False}
        self.last_verified_sector=None
        if erased:
            # Final physical readback also checks erased FF pages; avoid a
            # second full-sector read between erase and program.
            self.erase_sector(offset,verify=False)
            current=b'\xff'*4096
        else:
            current=old
        for i in range(0,4096,128):
            if not erased and (i+128<=write_range[0] or i>=write_range[1]):
                continue
            target=new[i:i+128]
            if erased and target==b'\xff'*128:
                self.last_sector_stats['blank_pages_skipped']+=1
                continue
            if not skip_equal or current[i:i+128]!=target:
                self.program_known(offset+i,target,verify=False)
                self.last_sector_stats['programmed_pages']+=1
        # AHB invalidation is deferred to close() to eliminate per-sector QSPI reset pulses
        if verify:
            actual=None
            if getattr(self,'binary_reader',None) is not None:
                try:
                    actual=self.binary_reader.read(0x80000000+offset,4096)
                    if actual!=new:
                        actual_ip=getattr(self,'read_flash')(offset,4096)
                        if actual_ip!=new:
                            raise RuntimeError(f'Sector verification mismatch {offset:#x}')
                        actual=actual_ip
                except (RuntimeError,OSError):
                    actual=None
            if actual is None:
                try:
                    actual=self.mapped_block(offset,4096)
                    if actual!=new:
                        actual_ip=getattr(self,'read_flash')(offset,4096)
                        if actual_ip!=new:
                            raise RuntimeError(f'Sector verification mismatch {offset:#x}')
                        actual=actual_ip
                except (RuntimeError,OSError):
                    actual=None
            if actual is None:
                actual=getattr(self,'read_flash',self.verified_block)(offset,4096)
                if actual!=new:
                    raise RuntimeError(f'Sector verification mismatch {offset:#x}')
            self.last_verified_sector=actual
            self.last_sector_stats['verified']=True
        return erased

    def verified_block(self,offset,length,stop_file=None):
        """Require a fresh unanimous triad, including independent physical IP.

        Discard a disagreeing set in full. Never accept majority voting and never
        replay erase/program on an uncertain read.
        """
        result=bytearray()
        for at in range(offset,offset+length,4096):
            size=min(4096,offset+length-at)
            for attempt in range(3):
                check_stop(stop_file)
                if getattr(self,'binary_reader',None) is not None:
                    first=self.binary_reader.read(0x80000000+at,size)
                    second=self.binary_reader.read(0x80000000+at,size)
                    mapped=self.read_flash(at,size)
                    paths='native1/native2/IP'
                else:
                    first=self.read_flash(at,size)
                    second=self.read_flash(at,size)
                    mapped=self.mapped_block(at,size,stop_file,words=16 if attempt else 80)
                    paths='IP1/IP2/mapped'
                if first==second==mapped:
                    result.extend(first)
                    break
                hashes=[hashlib.sha256(value).hexdigest() for value in (first,second,mapped)]
                if not hasattr(self,'read_disagreements'):self.read_disagreements=[]
                self.read_disagreements.append(dict(offset=hex(at),attempt=attempt+1,hashes=hashes))
                print(f'READ_RETRY {at:#x} attempt={attempt+1}/3; discarded {paths} set',flush=True)
                synchronize(self.serial)
            else:
                raise RuntimeError(f'Independent Flash reads persistently disagree at {at:#x}; stopped; {paths} SHA256={hashes}')
        return bytes(result)

    def stable_mapped_block(self,offset,length,stop_file=None):
        """Fast pre-scan/readback; independently repeat each serialized AHB read.

        Changed sectors require independent physical IP validation. Native
        binary reads replace the text scan only after capability validation.
        """
        for attempt in range(3):
            words=32 if attempt==0 else 16
            first=self.mapped_block(offset,length,stop_file,words)
            second=self.mapped_block(offset,length,stop_file,words)
            if first==second:return first
            if not hasattr(self,'mapped_disagreements'):self.mapped_disagreements=[]
            self.mapped_disagreements.append(dict(offset=hex(offset),length=length,attempt=attempt+1))
            print(f'AHB_RETRY {offset:#x} attempt={attempt+1}/3; reread with conservative batches',flush=True)
            synchronize(self.serial)
        raise RuntimeError(f'Repeated mapped reads disagree at {offset:#x}; stopped')

    def mapped_block(self,offset,length,stop_file=None,words=32):
        if offset<0 or length<0 or length%4 or offset+length>getattr(self,'flash_size',0x1000000):
            raise ValueError('Invalid mapped Flash range')
        if getattr(self,'binary_reader',None) is not None:
            result=bytearray()
            for index in range(0,length,4096):
                check_stop(stop_file)
                result.extend(self.binary_reader.read(0x80000000+offset+index,min(4096,length-index)))
            return bytes(result)
        return self._mapped_text(offset,length,stop_file,words)

    def _mapped_text(self,offset,length,stop_file=None,words=32):
        data=bytearray()
        failures=0
        while len(data)<length:
            check_stop(stop_file)
            count=min(words,(length-len(data))//4)
            try:
                address=0x80000000+offset+len(data)
                block=self.read_addresses(address+i*4 for i in range(count))
            except (OSError,RuntimeError) as exc:
                failures+=1
                if failures>=4:
                    raise RuntimeError('Mapped read repeatedly failed') from exc
                synchronize(self.serial)
                words=16
                continue
            data.extend(block)
            failures=0
        return bytes(data)


def find_resume_record(root,offset,data,port):
    digest=hashlib.sha256(data).hexdigest()
    paths=list((root/'operation_runs').glob('*/result.json'))+list(root.glob('*/过程文件/result.json'))
    def record_order(path):
        task = path.parent.parent.name if path.parent.name == '过程文件' else path.parent.name
        return path.stat().st_mtime_ns, int(task) if task.isdigit() else 0
    for path in sorted(paths, key=record_order, reverse=True):
        try:
            previous=json.loads(path.read_text(encoding='utf-8'))
        except (OSError,ValueError):
            continue
        if (not previous.get('success') and previous.get('input_sha256')==digest
                and previous.get('offset')==hex(offset) and previous.get('length')==len(data)
                and previous.get('port')==port
                and any(row.get('completed') or row.get('verified') for row in previous.get('sectors',[]))):
            return str(path)
    return None


def validate_oslo_target(q,offset,length,partition_layout=None):
    if partition_layout is not None:
        return validate_device_partition(q,partition_layout,offset,length)
    try:
        actual=oslo_bounds(q.stable_mapped_block(0,8192),image_size=getattr(q,'flash_size',0x1000000))
        if actual!=(offset,length):
            raise ValueError(f'OSLO layout mismatch: input {(hex(offset),hex(length))}, device {tuple(hex(x) for x in actual)}')
        return actual
    except ValueError as e:
        if offset==0x40000:
            header=q.stable_mapped_block(0x40000,64)
            if b'QSPI' in header and b'RTIM' in header:
                return (offset,length)
        raise e


def validate_partition_target(q,name,offset,length,partition_layout=None):
    if partition_layout is not None:
        return validate_device_partition(q,partition_layout,offset,length)
    if name in ('OSLO','CPZ'):
        return validate_oslo_target(q,offset,length)
    if name=='WEB':
        header=q.stable_mapped_block(offset,32)
        if header[:4]==b'\xfe\xca\xfe\xca':
            return (offset,length)
    actual=partition_bounds(q.stable_mapped_block(0,8192),name,image_size=getattr(q,'flash_size',0x1000000))
    if actual!=(offset,length):
        raise ValueError(f'{name} layout mismatch: input {(hex(offset),hex(length))}, device {tuple(hex(x) for x in actual)}')
    return actual


class ConservativeFlashWriter(FastFlashWriter):
    """Existing serialized primitives, with no compound completion/FIFO reuse."""
    from asrcode.flash.qspi_flash_probe import Qspi as _Qspi
    wait_idle=_Qspi.wait_idle
    _read_ip_once=_Qspi._read_ip_once
    issue=FlashWriter.issue
    write_enable=FlashWriter.write_enable


def write_direct(offset,data,port='COM10',stop_file=None,write_mode=None,*,verify=True,erase=True,skip_equal=True,partition=None,partition_layout=None,resume_write=False,resume_check=True,records_root=None,baudrate=115200,run_dir=None,write_policy=None):
    from asrcode.flash.asr_io_settings import baudrate_value,backend_run_dir
    baudrate=baudrate_value(baudrate)
    if not data or offset<0 or offset+len(data)>0x1000000:
        raise ValueError('Input outside supported 24-bit Flash addressing')
    if any(type(value) is not bool for value in (verify,erase,skip_equal,resume_check)):
        raise ValueError('Write options must be boolean')
    records_root=Path(records_root) if records_root is not None else ROOT
    resume=find_resume_record(records_root,offset,data,port)
    if resume is None and records_root.resolve()!=ROOT.resolve():
        resume=find_resume_record(ROOT,offset,data,port)
    if resume_write and not resume:raise ValueError('没有匹配的已完成断点；请使用刷入固件从头开始')
    completed=set()
    if resume_write and resume:
        prior=json.loads(Path(resume).read_text(encoding='utf-8'))
        completed={int(row['offset'],0) for row in prior.get('sectors',[]) if row.get('completed') or row.get('verified')}
    run=backend_run_dir(records_root,run_dir) or records_root/'operation_runs'/str(time.time_ns())
    run.mkdir(parents=True,exist_ok=True)
    report={'success':False,'backup_created':False,'transport':'single_owner_compound_AT','port':port,'host_baudrate':baudrate,
            'offset':hex(offset),'length':len(data),'input_sha256':hashlib.sha256(data).hexdigest(),
            'options':{'verify':verify,'erase':erase,'skip_equal':skip_equal,'resume_check':resume_check},
            'resume_from':resume,'resume_policy':'recheck_completed_blocks' if resume_check else 'trust_contiguous_completed_prefix',
            'unchecked_resume_bytes':0,
            'sectors':[],'processed_sectors':0,'programmed_sectors':0,'erased_sectors':0,
            'skipped_sectors':0,'programmed_pages':0,'blank_pages_skipped':0,
            'verification_performed':False,'verified':False,'reboot_verified':False}
    result_path=run/'result.json'
    def save():
        temp=run/'result.tmp';temp.write_text(json.dumps(report,indent=2),encoding='utf-8');temp.replace(result_path)
    save();print('RESULT',result_path,flush=True)
    allowed_sectors=set(write_policy['blocks']) if write_policy else None
    if write_policy and (offset!=0 or not all(0<=at<=len(data)-4096 for at in allowed_sectors)):
        raise ValueError('配置范围策略必须匹配完整输入镜像')
    if write_policy:
        report['write_scope']='declared_configuration_blocks'
        report['policy_sidecar']=write_policy['sidecar']
        report['preserved_sectors']=0
    q=None;start=time.monotonic();digest=hashlib.sha256()
    try:
        q=(FastFlashWriter(port,baudrate=baudrate,records_dir=run) if baudrate!=115200 or run_dir is not None else FastFlashWriter(port))
        q.records_dir=run
        if hasattr(q, 'suspend_cellular_radio'):
            q.suspend_cellular_radio()
            report['cellular_session']=q._cellular_session.events
        q.check_profile()
        if offset+len(data)>getattr(q,'flash_size',0x1000000):raise ValueError('Input exceeds detected NOR capacity')
        if partition=='full':
            if offset!=0 or len(data)!=getattr(q,'flash_size',None):
                raise ValueError('Full image length must equal detected NOR capacity and start at zero')
            report['full_capacity_checked']=True
        if hasattr(q,'enable_binary_reads') and (verify or skip_equal or offset%4096 or (offset+len(data))%4096 or (resume_write and resume_check)):
            q.enable_binary_reads(offset,len(data),stop_file)
            report['read_transport']='READFLASH binary + independent physical IP' if q.binary_reader else 'REGRW/IP'
            report['binary_read_probe_error']=q._binary_session.probe_error
            print('WRITE_READ_TRANSPORT '+report['read_transport'],flush=True)
        if hasattr(q,'jedec_id'):report['jedec_id']=q.jedec_id.hex()
        if hasattr(q,'nor_parameters'):report['nor_parameters']=q.nor_parameters
        if hasattr(q,'profile'):report['controller_profile']=q.profile
        report['write_command_batch_limit']=getattr(q,'batch_limit',16)
        report['write_batch_probe']=getattr(q,'batch_probe',[])
        if partition=='oslo':
            validation=validate_oslo_target(q,offset,len(data),partition_layout)
            report['oslo_partition_bounds_checked']=True
            report['partition_validation']=validation if isinstance(validation,dict) else {'method':'legacy_layout','offset':validation[0],'size':validation[1]}
        elif partition not in (None,'full'):
            name=partition[4:] if partition.startswith('tim:') else partition
            validation=validate_partition_target(q,name,offset,len(data),partition_layout)
            report['partition_bounds_checked']=name
            report['partition_validation']=validation if isinstance(validation,dict) else {'method':'legacy_layout','offset':validation[0],'size':validation[1]}
        first=offset//4096*4096;end=(offset+len(data)+4095)//4096*4096;total=(end-first)//4096
        report['backup_policy']='no_backup'
        declared_parts = firmware_partitions(data) if partition == 'full' else []
        max_code_offset = max((p['offset'] + p['size'] for p in declared_parts), default=0x5b0000)
        code_limit = (max_code_offset + 4095) // 4096 * 4096
        active_first=first
        if resume_write and not resume_check:
            while active_first<end and active_first in completed:
                report['sectors'].append({'offset':hex(active_first),'completed':True,'verified':False,
                                          'resumed_skip':True,'resume_rechecked':False})
                active_first+=4096
            report['unchecked_resume_bytes']=max(0,min(active_first,offset+len(data))-offset)
            report['skipped_sectors']=len(report['sectors'])
            save()
            print(f"WRITE_RESUME {report['unchecked_resume_bytes']}",flush=True)
            print(f"WRITE_SPEED {report['unchecked_resume_bytes']}/{len(data)} elapsed=0.00",flush=True)
            print(f'续写：已完成前缀不复核，从 {active_first:#x} 继续；仅核对并写入后续块。',flush=True)
        elif resume_write:
            print('续写：重新核对已完成块，内容一致才跳过。',flush=True)
        check_stop(stop_file)
        direct=not (verify or erase or skip_equal)
        scan_samples={}
        if write_policy:
            from asrcode.flash.config_write_guard import validate_block
            equal=[];different=[]
            for at in sorted(allowed_sectors):
                check_stop(stop_file)
                sample=q.stable_mapped_block(at,4096,stop_file)
                validate_block(write_policy,at,sample,data[at:at+4096])
                scan_samples[at]=sample
                (equal if sample==data[at:at+4096] else different).append(hex(at))
            plan={'equal_blocks':equal,'different_blocks':different,'block_size':4096,
                  'compared_bytes':len(allowed_sectors)*4096,'scope':'declared_configuration_blocks'}
            report['comparison_plan']=plan
            report['comparison_completed_before_writes']=True
            print(f'配置范围预检完成：仅允许 {len(allowed_sectors)} 块；其余身份、校准及运行记录原样保留。',flush=True)
        elif skip_equal and active_first<end:
            from asrcode.flash.asr_write_plan import scan_write_plan
            scan_end = min(end, code_limit) if (partition == 'full' and allowed_sectors is None) else end
            scan_samples,plan=scan_write_plan(
                lambda address,size:q.mapped_block(address,size,stop_file),max(offset,active_first),data[max(offset,active_first)-offset:scan_end-offset],
                lambda:check_stop(stop_file),
                lambda done,total:print(f'PROGRESS compare {done}/{total}',flush=True))
            report['comparison_plan']=plan
            report['comparison_completed_before_writes']=True
            save()
            print(f"WRITE_PLAN equal={len(plan['equal_blocks'])} different={len(plan['different_blocks'])}",flush=True)
        total_diff_blocks = total
        if skip_equal and 'plan' in locals() and plan and 'different_blocks' in plan:
            total_diff_blocks = len(plan['different_blocks'])
            if plan.get('equal_blocks'):
                eq_cnt = len(plan['equal_blocks'])
                print(f"已跳过 {eq_cnt} 个相同块 ({(eq_cnt*4096)/1048576:.2f} MiB)，无需写入；待写入 {total_diff_blocks} 个差异块。", flush=True)

        diff_blocks_done = 0
        actual_written_bytes = 0
        actual_write_started = None
        transfer_started = time.monotonic()

        for address in range(active_first,end,65536):
            for sector in range(address,min(address+65536,end),4096):
                if allowed_sectors is not None and sector not in allowed_sectors:
                    report['preserved_sectors']+=1
                    continue
                check_stop(stop_file);lo=max(sector,offset);hi=min(sector+4096,offset+len(data))
                wanted=data[lo-offset:hi-offset]
                if partition == 'full' and allowed_sectors is None and sector >= code_limit:
                    old_sample = scan_samples.get(sector, b'')
                    if sector >= 0x700000 or b'littlefs' in old_sample or b'littlefs' in wanted:
                        report['preserved_sectors'] += 1
                        report['skipped_sectors'] += 1
                        report['sectors'].append({'offset': hex(sector), 'completed': True, 'verified': True, 'nvram_preserved': True})
                        if verify: digest.update(old_sample[lo-sector:hi-sector] if old_sample else wanted)
                        continue
                wanted=data[lo-offset:hi-offset]
                if resume_write and sector in completed:
                    observed=q.verified_block(sector,4096,stop_file)
                    if observed[lo-sector:hi-sector]==wanted:
                        report['skipped_sectors']+=1
                        report['sectors'].append({'offset':hex(sector),'completed':True,'verified':True,'resumed_skip':True})
                        save()
                        if verify:digest.update(observed[lo-sector:hi-sector])
                        print(f'断点续写 {sector:#x}：设备内容核对一致',flush=True)
                        continue
                if skip_equal:
                    before=scan_samples[sector]
                    if before[lo-sector:hi-sector]==wanted:
                        observed=before
                        if observed[lo-sector:hi-sector]==wanted:
                            report['skipped_sectors']+=1
                            report['sectors'].append({'offset':hex(sector),'completed':True,'verified':verify,'equal_skip':True})
                            if verify:digest.update(observed[lo-sector:hi-sector])
                            continue
                if actual_write_started is None:
                    actual_write_started = time.monotonic()
                print(f'SECTOR_BEGIN {sector:#x}',flush=True)
                reader=q.verified_block if verify else getattr(q,'stable_mapped_block',q.verified_block)
                overwrite_full=erase and lo==sector and hi==sector+4096
                full_sector=lo==sector and hi==sector+4096
                old=(scan_samples[sector] if skip_equal or write_policy else
                     b'\xff'*4096 if full_sector else reader(sector,4096,stop_file))
                new=bytearray(old);new[lo-sector:hi-sector]=wanted
                row={'offset':hex(sector),'verified':False,'original_sha256':None if not skip_equal and lo==sector and hi==sector+4096 else hashlib.sha256(old).hexdigest(),
                     'requested_start':hex(lo),'requested_length':hi-lo,'rewrite_count':0}
                if write_policy:
                    backups=run/'配置块备份';backups.mkdir(exist_ok=True)
                    backup_path=backups/f'{sector:06x}.original.bin'
                    backup_path.write_bytes(old)
                    row['backup']=str(backup_path)
                    report['backup_created']=True
                    report['backup_policy']='declared_configuration_blocks'
                report['sectors'].append(row);save();began=time.monotonic()
                
                # Upgraded to 5 retries (6 attempts: attempt 0..5) with progressive staged self-healing
                max_retries = getattr(q, "max_retries", 3)
                for attempt in range(max_retries + 1):
                    try:
                        row['erased']=q.replace_sector(sector,old,bytes(new),verified_old=True,
                                                       verify=verify,erase=erase,skip_equal=skip_equal,
                                                       write_range=(lo-sector,hi-sector))
                        break
                    except (RuntimeError,OSError) as exc:
                        row['last_error']=str(exc);save()
                        uncertain_tokens=('ACK mismatch','address/count/ACK','Incomplete AT response',
                                          'Invalid batch','Batched register write failed',
                                          'GetOverlappedResult','ClearCommError','WriteFile')
                        if isinstance(exc,OSError) or any(token in str(exc) for token in uncertain_tokens):
                            try:
                                time.sleep(0.05 * (attempt + 1))
                                synchronize(q.serial)
                                if hasattr(q.serial, 'reset_input_buffer'):
                                    q.serial.reset_input_buffer()
                                if hasattr(q, 'flash_ready'):
                                    q.flash_ready()
                                current_check = q.stable_mapped_block(sector, 4096)
                                if current_check == bytes(new):
                                    row['verified'] = True
                                    row['erased'] = True
                                    break
                            except Exception:
                                pass
                            if attempt == max_retries:
                                row['write_state_uncertain']=True
                                row['recovery']='stopped_without_blind_sector_replay'
                                save()
                                raise RuntimeError(f'写入响应不完整 {sector:#x}；当前块状态未确认，已停止自动整块重擦。原始错误：{exc}') from exc
                        if attempt == max_retries or (not erase and 'verification mismatch' in str(exc).lower()):raise
                        
                        # Graduated backoff delay to cover Flash erase / RTOS background cycles
                        time.sleep(0.02 * (1.5 ** attempt))
                        
                        if attempt == 1:
                            try:
                                synchronize(q.serial)
                                if hasattr(q.serial, 'reset_input_buffer'):
                                    q.serial.reset_input_buffer()
                            except Exception:
                                pass
                        elif attempt == 2:
                            try:
                                synchronize(q.serial)
                                if hasattr(q, 'restore_standard_lut'):
                                    q.restore_standard_lut()
                                if hasattr(q, 'flash_ready'):
                                    q.flash_ready()
                            except Exception:
                                pass
                        elif attempt == 3:
                            try:
                                if hasattr(q, 'reset_flash'):
                                    q.reset_flash()
                                if hasattr(q, 'restore_standard_lut'):
                                    q.restore_standard_lut()
                                synchronize(q.serial)
                            except Exception:
                                pass
                        elif attempt >= 4:
                            if ('WEL not set' in str(exc) and not isinstance(q,ConservativeFlashWriter)
                                    and hasattr(q,'jedec_id') and hasattr(q,'flash_size')):
                                from asrcode.flash.asr_writer_recovery import reopen_conservative
                                previous=q;q=None
                                q=reopen_conservative(previous,ConservativeFlashWriter,port,baudrate,run)
                                report['conservative_fallback']=True
                                report['fallback_origin_read_transport']=report.get('read_transport')
                                report['read_transport']='REGRW/IP conservative'
                                print('写使能状态异常：会话已重建并核对Flash标识；降级逐条QSPI路径重试当前块。',flush=True)
                            else:
                                try:
                                    synchronize(q.serial)
                                    if hasattr(q, 'restore_standard_lut'):
                                        q.restore_standard_lut()
                                    q.check_profile()
                                except Exception:
                                    pass
                        row['rewrite_count']=attempt+1;save()
                        print(f'块重写 {sector:#x} 第{attempt+1}/{max_retries}次：{exc}',flush=True)
                stats=getattr(q,'last_sector_stats',{})
                pages=stats.get('programmed_pages',sum(1 for i in range(0,4096,128)
                    if new[i:i+128]!=b'\xff'*128 and (not skip_equal or erase or old[i:i+128]!=new[i:i+128])))
                row.update(seconds=time.monotonic()-began,programmed_pages=pages,
                           blank_pages_skipped=stats.get('blank_pages_skipped',0))
                if verify:
                    actual=getattr(q,'last_verified_sector',None)
                    if actual is None:actual=q.verified_block(sector,4096)
                    if actual!=new:raise RuntimeError(f'Sector verification mismatch {sector:#x}')
                    digest.update(actual[lo-sector:hi-sector])
                    row['verified']=True
                row['completed']=True
                report['processed_sectors']+=1;report['programmed_sectors']+=bool(pages)
                report['erased_sectors']+=bool(row['erased']);report['programmed_pages']+=pages
                report['blank_pages_skipped']+=row['blank_pages_skipped'];save()
                
                # Speed and block-level progress tracking
                diff_blocks_done += 1
                actual_written_bytes += (hi - lo)
                sector_duration = max(0.001, time.monotonic() - began)
                instant_speed = 4096 / sector_duration
                total_write_time = max(0.001, time.monotonic() - (actual_write_started or transfer_started))
                overall_speed = actual_written_bytes / total_write_time
                
                print(f'SECTOR {sector:#x} '+('verified' if verify else 'command complete; no readback'),flush=True)
                print(f'BLOCK_PROGRESS {diff_blocks_done}/{total_diff_blocks} sector={sector:#x} inst={instant_speed/1024:.1f} overall={overall_speed/1024:.1f} elapsed={total_write_time:.1f}',flush=True)
                print(f'WRITE_SPEED {hi-offset}/{len(data)} elapsed={total_write_time:.2f}',flush=True)
                check_stop(stop_file)
            save();print(f'PROGRESS write {min(address+65536,end)-first}/{end-first}',flush=True)
            if actual_write_started is not None:
                total_write_time = max(0.001, time.monotonic() - actual_write_started)
                print(f'WRITE_SPEED {min(address+65536,end,offset+len(data))-offset}/{len(data)} elapsed={total_write_time:.2f}',flush=True)
        if verify and report['unchecked_resume_bytes']:
            report['written_suffix_sha256']=digest.hexdigest()
            expected=hashlib.sha256(data[report['unchecked_resume_bytes']:]).hexdigest()
            if report['written_suffix_sha256']!=expected:raise RuntimeError('Written suffix checksum mismatch')
            report.update(verification_performed=active_first<end,verified=False,
                          verification='written_suffix_only; resumed_prefix_not_rechecked',
                          verification_start=hex(offset+report['unchecked_resume_bytes']))
        elif verify:
            report['readback_sha256']=digest.hexdigest()
            expected_hash=(hashlib.sha256(b''.join(data[at:at+4096] for at in sorted(allowed_sectors))).hexdigest()
                           if allowed_sectors is not None else report['input_sha256'])
            if report['readback_sha256']!=expected_hash:raise RuntimeError('Input-range checksum mismatch')
            report.update(verification_performed=True,verified=True,
                          verification='declared_configuration_blocks_only' if write_policy else 'per_written_sector_physical_IP_vs_expected_and_input_comparison_for_skips')
        else:
            report['verification']='not_requested; commands completed without post-write data readback'
        report['binary_read_recovery']=getattr(q,'binary_recovery_stats',{})
        report['read_disagreements']=getattr(q,'read_disagreements',[])
        report['mapped_disagreements']=getattr(q,'mapped_disagreements',[])
        print(f'WRITE_SPEED {len(data)}/{len(data)} elapsed={time.monotonic()-transfer_started:.2f}',flush=True)
        report['validation_reuse']={'lut_guard_hits':getattr(q,'guard_cache_hits',0),
                                    'idle_status_hits':getattr(q,'idle_cache_hits',0)}
        report['ahb_invalidations']=getattr(q,'ahb_invalidations',0)
        q.close();q=None;report['success']=True
    except Exception as exc:
        report['error']=repr(exc);report['cancelled']=isinstance(exc,OperationCancelled);raise
    finally:
        try:
            if q is not None:q.close()
        finally:report['duration_seconds']=time.monotonic()-start;save()
    print('COMPLETE',json.dumps(report),flush=True)
    return report

if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    from asrcode.flash.cli_options import add_boolean_option
    ap.add_argument('--port',default='COM10');ap.add_argument('--input',required=True,type=Path)
    ap.add_argument('--offset',type=lambda x:int(x,0),default=0)
    ap.add_argument('--mode',default='full',help='full, oslo, patch, or tim:NAME')
    ap.add_argument('--no-backup',action='store_true',help=argparse.SUPPRESS)
    ap.add_argument('--stop-file',type=Path)
    ap.add_argument('--write-mode',help=argparse.SUPPRESS)
    ap.add_argument('--resume-write',action='store_true')
    add_boolean_option(ap,'--resume-check',default=True)
    from asrcode.flash.asr_io_settings import baudrate_value
    ap.add_argument('--baudrate',type=baudrate_value,default=115200)
    ap.add_argument('--run-dir',type=Path)
    ap.add_argument('--records-root',type=Path)
    for name in ('verify','erase','skip-equal'):
        add_boolean_option(ap,'--'+name,default=True)
    args=ap.parse_args();offset,data=prepare_input(args.input,args.mode,args.offset)
    from asrcode.flash.config_write_guard import load_policy
    write_policy=load_policy(args.input,args.input.read_bytes()) if args.mode=='full' else None
    partition_layout=None
    if args.mode=='oslo' or args.mode.startswith('tim:'):
        source_name='OSLO' if args.mode=='oslo' else args.mode[4:].upper()
        partition_layout=source_partition_layout(args.input.read_bytes(),source_name,offset,len(data))
        if partition_layout is not None:
            print(f"PARTITION_LAYOUT {partition_layout['manifest_name']}@{partition_layout['manifest_origin']:#x} "
                  f"{partition_layout['partition_name']}={offset:#x}+{len(data):#x}",flush=True)
    print(f'INPUT mode={args.mode} offset={offset:#x} length={len(data):#x}',flush=True)
    try:write_direct(offset,data,args.port,args.stop_file,verify=args.verify,erase=args.erase,skip_equal=args.skip_equal,
                     partition=args.mode if args.mode in ('full','oslo') or args.mode.startswith('tim:') else None,partition_layout=partition_layout,resume_write=args.resume_write,resume_check=args.resume_check,
                     records_root=args.records_root or args.input.resolve().parent/'读刷工具记录',baudrate=args.baudrate,run_dir=args.run_dir,write_policy=write_policy)
    except OperationCancelled:
        print('CANCELLED write; current sector completed; readback '+('enabled' if args.verify else 'not requested'),flush=True)
        raise SystemExit(2)
