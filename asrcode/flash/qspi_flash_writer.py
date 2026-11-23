"""Capability-detected QSPI NOR partial writer. Explicit offset, sector backup, IP readback."""
import argparse
import hashlib
import json
import struct
import time
from pathlib import Path
from asrcode.flash.asr_io_settings import read_metadata_path
from asrcode.flash.at_flash_backup import read_words
from asrcode.flash.qspi_flash_write_probe import WritableQspi, ROOT

FLASH_SIZE=0x800000
SECTOR_SIZE=4096


def needs_erase(old,new):
    if len(old)!=len(new):
        raise ValueError('Length mismatch')
    return any((a&b)!=b for a,b in zip(old,new))


class FlashWriter(WritableQspi):
    def restore_standard_lut(self):
        """Restore standard ASR QSPI LUT slots (slot 1: wren 0x406) if corrupted by background RTOS."""
        try:
            if hasattr(self, 'wait_idle'):
                self.wait_idle()
            lock = self.read(0x304) if hasattr(self, 'read') else 1
            if hasattr(self, 'write'):
                self.write(0x300, 0x5af05af0)
                self.write(0x304, 2)
                # Standard WREN in slot 14 (0x3f0) or slot 1 (0x320)
                self.write(0x3f0, 0x406)
                self.write(0x3f4, 0)
                self.write(0x3f8, 0)
                self.write(0x3fc, 0)
                # Ensure slot 15 is clean
                for i in range(4):
                    self.write(0x400 + i * 4, 0)
                self.write(0x300, 0x5af05af0)
                self.write(0x304, lock)
        except Exception:
            pass

    def check_profile(self):
        from asrcode.flash.qspi_profile import discover_profile
        try:
            self.profile=discover_profile(lambda address,count:read_words(self.serial,address,count))
        except ValueError as exc:
            if 'Unsupported QSPI NOR command capability' in str(exc):
                self.restore_standard_lut()
                self.profile=discover_profile(lambda address,count:read_words(self.serial,address,count))
            else:
                raise
        for attempt in range(2):
            try:
                self.jedec_id=self.read_jedec()
                # Standard SPI NOR density byte is log2(capacity in bytes).
                density=self.jedec_id[2]
                if self.jedec_id[0] in (0,255) or not 20<=density<=25:
                    raise RuntimeError('Unsupported SPI NOR JEDEC ID: '+self.jedec_id.hex())
                self.flash_size=1<<density
                from asrcode.flash.qspi_profile import parse_sfdp
                instructions=(0x0818045a,0x1c000c08,0,0)
                sfdp=self.read_special(instructions,0,128)
                self.nor_parameters=parse_sfdp(sfdp,lambda offset,length:self.read_special(instructions,offset,length))
                if self.flash_size!=self.nor_parameters['capacity']:
                    raise RuntimeError('JEDEC density and SFDP capacity disagree')
                break
            except RuntimeError:
                if attempt:raise
                print('NOR探测异常，恢复协议状态后重试一次',flush=True)
                self.reset_flash()
        from asrcode.flash.asr_flash_session import FlashProtectionSession
        self._flash_protection=FlashProtectionSession(self.serial)
        # The protection layout comes from the NOR capability descriptor, not
        # the ASR device model or firmware version. Unknown layouts retain the
        # existing BP path instead of guessing another vendor's status bits.
        from asrcode.flash.qspi_profile import complementary_protection
        sr2=(lambda:self.read_special((0x1c000435,0,0,0),0,1)[0]) if complementary_protection(self.jedec_id,self.nor_parameters) else None
        self._flash_protection.start(lambda:self.read_special((0x1c000405,0,0,0),0,1)[0],sr2)

    def _restore_flash_protection(self):
        session=getattr(self,'_flash_protection',None)
        self._flash_protection=None
        if session is not None:session.close()

    def read_ip(self,seq,address,length):
        if hasattr(self,'profile'):
            seq=self.profile['sequences'].get({2:'status',3:'read'}.get(seq,''),seq)
        return super().read_ip(seq,address,length)

    def issue(self,seq,offset=0,data=b''):
        if hasattr(self,'profile') and seq in (1,6):
            from asrcode.flash.qspi_profile import expected_registers
            name={1:'wren',6:'program'}[seq]
            for register,value in expected_registers(self.profile,[name]).items():
                if self.read(register)!=value:raise RuntimeError('QSPI command sequence changed')
            seq=self.profile['sequences'][name]
        return super().issue(seq,offset,data)

    def write_enable(self):
        for _ in range(3):
            self.flash_ready()
            self.issue(1)
            if self.flash_ready() & 2:
                return
            time.sleep(0.005)
        raise RuntimeError('NOR write enable did not latch')

    def read_jedec(self):
        id_bytes = b'\x00\x00\x00'
        for _ in range(3):
            id_bytes = self.read_special((0x1c00049f,0,0,0),0,3)
            if len(id_bytes) >= 3 and id_bytes[0] not in (0, 0xff, 0x03) and 20 <= id_bytes[2] <= 25:
                return id_bytes
            time.sleep(0.05)
        return id_bytes

    def read_special(self,instructions,offset,length):
        if not 0<length<=128:raise ValueError('Special NOR read exceeds FIFO')
        saved=[self.read(0x400+i*4) for i in range(4)]
        lock=self.read(0x304)
        try:
            self.wait_idle()
            self.write(0x300,0x5af05af0);self.write(0x304,2)
            for i,value in enumerate(instructions):self.write(0x400+i*4,value)
            self.write(0,self.read(0)|0x400)
            self.write(0x16c,0x100);self.write(0x100,0x80000000+offset)
            self.write(0x110,0x100|((length+3)//4-1));self.write(0x160,0xffffffff)
            self.write(8,(15<<24)|length);self.wait_idle()
            for _ in range(50):
                if self.read(0x160) & 1:
                    break
                time.sleep(0.005)
            flags=self.read(0x160)
            if flags&0xd0:raise RuntimeError('Special NOR read command failed: '+hex(flags))
            if not flags&1:raise RuntimeError('Special NOR read did not complete; FIFO discarded')
            return read_words(self.serial,0xd420b200,(length+3)//4)[:length]
        finally:
            self.wait_idle()
            self.write(0x300,0x5af05af0);self.write(0x304,2)
            for i,value in enumerate(saved):self.write(0x400+i*4,value)
            self.write(0x304,lock)

    def reset_flash(self):
        """Send standard JEDEC SPI NOR Enable Reset (0x66) + Reset (0x99) sequence."""
        saved=[self.read(0x400+i*4) for i in range(4)]
        lock=self.read(0x304)
        try:
            self.wait_idle()
            self.write(0x300,0x5af05af0);self.write(0x304,2)
            # 1. Enable Reset (0x66)
            for i,val in enumerate([0x0466,0,0,0]):self.write(0x400+i*4,val)
            self.write(0x16c,0x100);self.write(0x100,0x80000000)
            self.write(0x160,self.read(0x160))
            self.write(8,15<<24);self.wait_idle()
            # 2. Reset Device (0x99)
            for i,val in enumerate([0x0499,0,0,0]):self.write(0x400+i*4,val)
            self.write(0x16c,0x100);self.write(0x100,0x80000000)
            self.write(0x160,self.read(0x160))
            self.write(8,15<<24);self.wait_idle()
            time.sleep(0.05)
        except Exception:
            pass
        finally:
            try:
                self.wait_idle()
                self.write(0x300,0x5af05af0);self.write(0x304,2)
                for i,val in enumerate(saved):self.write(0x400+i*4,val)
                self.write(0x300,0x5af05af0);self.write(0x304,lock)
            except Exception:
                pass

    def close(self):
        try:
            self._restore_flash_protection()
        finally:
            super().close()

    def read_flash(self,offset,length):
        if offset<0 or length<0 or offset+length>getattr(self,'flash_size',FLASH_SIZE):
            raise ValueError('Flash range exceeds detected capacity')
        return b''.join(self.read_ip(3,0x80000000+offset+i,min(128,length-i))
                        for i in range(0,length,128))

    def program(self,offset,data):
        if not 0<=offset<getattr(self,'flash_size',FLASH_SIZE) or offset+len(data)>getattr(self,'flash_size',FLASH_SIZE):
            raise ValueError('Flash range exceeds detected capacity')
        if not 1<=len(data)<=128 or offset//256!=(offset+len(data)-1)//256:
            raise ValueError('Chunk crosses page boundary or exceeds FIFO')
        old=self.read_flash(offset,len(data))
        if needs_erase(old,data):
            raise ValueError('Programming requires an erased destination')
        self.write_enable()
        self.issue(6,offset,data)
        self.flash_ready()
        if self.read_flash(offset,len(data))!=data:
            raise RuntimeError(f'Program verification failed at {offset:#x}')

    def erase_sector(self,offset,verify=True):
        if offset%SECTOR_SIZE or not 0<=offset<=getattr(self,'flash_size',FLASH_SIZE)-SECTOR_SIZE:
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
            self.flash_ready()
            if verify and self.read_flash(offset,SECTOR_SIZE)!=b'\xff'*SECTOR_SIZE:
                raise RuntimeError(f'Erase verification failed at {offset:#x}')
        finally:
            self.write(0x300,0x5af05af0)
            self.write(0x304,2)
            for i,value in enumerate(saved):
                self.write(0x400+i*4,value)
            self.write(0x300,0x5af05af0)
            self.write(0x304,lock)

    def replace_sector(self,offset,old,new):
        if len(old)!=SECTOR_SIZE or len(new)!=SECTOR_SIZE:
            raise ValueError('Expected complete 4 KiB sectors')
        if self.read_flash(offset,SECTOR_SIZE)!=old:
            raise RuntimeError('Sector changed since backup; stopped before erase')
        erased=needs_erase(old,new)
        if erased:
            self.erase_sector(offset)
            current=b'\xff'*SECTOR_SIZE
        else:
            current=old
        for i in range(0,SECTOR_SIZE,128):
            if current[i:i+128]!=new[i:i+128]:
                self.program(offset+i,new[i:i+128])
        if self.read_flash(offset,SECTOR_SIZE)!=new:
            raise RuntimeError(f'Sector verification failed at {offset:#x}')
        return erased


def write_patch(offset,data,port="COM10",backup_root=None):
    if not data or offset<0 or offset+len(data)>0x1000000:
        raise ValueError('Input exceeds supported 24-bit Flash addressing')
    directory=Path(backup_root or ROOT/'flash_write_backups')/str(time.time_ns())
    directory.mkdir(parents=True)
    report={'offset':hex(offset),'length':len(data),
            'input_sha256':hashlib.sha256(data).hexdigest(),
            'success':False,'port':port,'sectors':[]}
    manifest=directory/'manifest.json'
    def save():
        manifest.write_text(json.dumps(report,indent=2),encoding='utf-8')
    save()
    q=None
    try:
        q=FlashWriter(port)
        q.check_profile()
        if offset+len(data)>q.flash_size:raise ValueError('Input exceeds detected NOR capacity')
        sectors=[]
        first=offset//SECTOR_SIZE*SECTOR_SIZE
        end=(offset+len(data)+SECTOR_SIZE-1)//SECTOR_SIZE*SECTOR_SIZE
        total=(end-first)//SECTOR_SIZE
        for index,address in enumerate(range(first,end,SECTOR_SIZE),1):
            old=q.read_flash(address,SECTOR_SIZE)
            new=bytearray(old)
            lo=max(address,offset)
            hi=min(address+SECTOR_SIZE,offset+len(data))
            new[lo-address:hi-address]=data[lo-offset:hi-offset]
            name=f'{address:06x}.original.bin'
            (directory/name).write_bytes(old)
            row={'offset':hex(address),'backup':name,
                 'original_sha256':hashlib.sha256(old).hexdigest(),'verified':False}
            report['sectors'].append(row)
            sectors.append((address,old,bytes(new),row))
            save()
            print(f'PROGRESS backup {index}/{total}',flush=True)
        print(f'BACKUP {directory}',flush=True)
        for index,(address,old,new,row) in enumerate(sectors,1):
            row['erase_required']=needs_erase(old,new)
            save()
            row['erased']=q.replace_sector(address,old,new)
            row['verified']=True
            save()
            print(f'PROGRESS write {index}/{total}',flush=True)
            print(f'VERIFIED sector={address:#x} erased={row["erased"]}',flush=True)
        q.close()
        q=None
        report['success']=True
        save()
        print(f'RESULT {manifest}',flush=True)
        return report
    except Exception as exc:
        report['error']=repr(exc)
        save()
        raise
    finally:
        if q is not None:
            q.close()


def tim_partitions(data,image_size=None):
    """Return validated, non-overlapping extents declared by TIM, including TIMH."""
    if len(data)<56 or data[4:8]!=b'HMIT':
        raise ValueError('Not a raw HMIT firmware image')
    count=struct.unpack_from('<I',data,44)[0]
    table_end=56+count*96
    if not 1<=count<=64 or table_end>len(data):
        raise ValueError('Invalid TIM image table')
    limit=len(data) if image_size is None else image_size
    rows=[];names=set()
    for i in range(count):
        at=56+i*96
        try:name=data[at:at+4][::-1].decode('ascii')
        except UnicodeDecodeError:raise ValueError('Invalid TIM image name') from None
        if len(name)!=4 or any(c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_' for c in name) or name in names:
            raise ValueError('Invalid or duplicate TIM image name: '+repr(name))
        start=struct.unpack_from('<I',data,at+8)[0]
        size=struct.unpack_from('<I',data,at+16)[0]
        if not size or start+size>limit or (name!='TIMH' and start<table_end):
            raise ValueError(name+' extent lies outside the input image or intersects TIM table')
        if name=='TIMH' and (start!=0 or size<table_end):
            raise ValueError('Invalid TIMH extent')
        if any(start<r['offset']+r['size'] and r['offset']<start+size for r in rows):
            raise ValueError(name+' overlaps another TIM image')
        names.add(name);rows.append({'name':name,'offset':start,'size':size})
    return rows


def detect_web_partition(data):
    """Detect Adler32-verified WebUI filesystem (fecafeca header)."""
    import zlib
    from asrcode.firmware.fwdecon.hmit import Firmware, FECACE, HEAD
    start = 0
    while True:
        start = data.find(FECACE, start)
        if start < 0:
            break
        if start % 4096 == 0 and start >= 0x400000:
            end = Firmware._chain_end(data, start + HEAD)
            if end and (zlib.adler32(data[start + 8:end]) & 0xffffffff) == struct.unpack_from('<I', data, start + 4)[0]:
                size = (end - start + 4095) // 4096 * 4096
                return start, size
        start += 4
    return None


def firmware_partitions(data,image_size=None):
    """Return all partitions using universal partition discovery: TIM-declared, CPZ, and verified WEB."""
    try:
        from asrcode.firmware.partitions import discover_universal_partitions
        return discover_universal_partitions(data)
    except Exception:
        pass
    rows = tim_partitions(data, image_size)
    names = {r['name'] for r in rows}
    if 'OSLO' not in names:
        try:
            from asrcode.firmware.fwdecon.cpz_region import application_region
            start, size, _ = application_region(data)
            rows.append({'name': 'CPZ', 'offset': start, 'size': size, 'desc': '核心应用段 (CPZ应用段)'})
            names.add('CPZ')
        except Exception:
            pass
    if 'WEB' not in names and 'WEBI' not in names:
        web = detect_web_partition(data)
        if web:
            web_start, web_size = web
            if not any(web_start < r['offset'] + r['size'] and r['offset'] < web_start + web_size for r in rows):
                rows.append({'name': 'WEB', 'offset': web_start, 'size': web_size, 'desc': '网页文件系统 (WEB)'})
                names.add('WEB')
    rows.sort(key=lambda x: x['offset'])
    return rows


def partition_bounds(data,name,image_size=None):
    try:
        from asrcode.firmware.partitions import slice_universal_partition
        start, slice_data, info = slice_universal_partition(data, name)
        return start, len(slice_data)
    except Exception:
        pass
    parts = firmware_partitions(data, image_size)
    rows = [r for r in parts if r['name'] == name]
    if not rows and name == 'OSLO':
        rows = [r for r in parts if r['name'] == 'CPZ']
    if len(rows) != 1:
        raise ValueError('TIM must contain exactly one ' + name + ' image')
    return rows[0]['offset'], rows[0]['size']


def oslo_bounds(data,image_size=None):
    """Read the OSLO extent from the validated TIM image table or CPZ application fallback."""
    return partition_bounds(data,'OSLO',image_size)


def prepare_input(path,mode,offset=0):
    data=Path(path).read_bytes()
    if data[4:8] == b'HMIT':
        from asrcode.flash.asr_tim_integrity import require_valid
        try:
            require_valid(data)
        except Exception:
            pass
    full=len(data) in (0x100000,0x200000,0x400000,0x800000,0x1000000) and data[4:8]==b'HMIT'
    if mode=='full':
        if not full:raise ValueError('Expected a raw HMIT image with a supported capacity')
        return 0,data
    if mode=='patch':
        if not data or offset<0 or offset+len(data)>0x1000000:
            raise ValueError('Input must fit in supported 24-bit Flash addressing')
        return offset,data

    if mode.startswith('tim:') or mode in ('oslo', 'cpz', 'web', 'webi'):
        if full:
            try:
                from asrcode.firmware.partitions import slice_universal_partition
                start, slice_data, info = slice_universal_partition(data, mode, offset)
                return start, slice_data
            except Exception:
                pass
        name = mode[4:] if mode.startswith('tim:') else ('WEB' if mode in ('web', 'webi') else ('CPZ' if mode == 'cpz' else 'OSLO'))
        if not full:
            metadata=read_metadata_path(path)
            info=json.loads(metadata.read_text(encoding='utf-8')) if metadata.exists() else {}
            if not info.get('complete') or info.get('partition',{}).get('name')!=name:
                raise ValueError('原始分卷需要匹配读取记录，校验不匹配，请重新读取')
            if info.get('sha256') and hashlib.sha256(data).hexdigest()!=info['sha256']:
                raise ValueError('文件损坏或读取记录不一致，请核对文件')
            start=int(info['base_address'],0)-0x80000000
            if not data or start<0 or start+len(data)>0x1000000:raise ValueError('Invalid raw partition extent')
            return start,data
        start,size=partition_bounds(data,name)
        return start,data[start:start+size]
    raise ValueError('Unknown write mode: '+str(mode))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--offset',default=0,type=lambda x:int(x,0))
    parser.add_argument('--port',default='COM10')
    parser.add_argument('--mode',default='patch',help='patch, oslo, full, or tim:NAME')
    parser.add_argument('--backup-dir',type=Path)
    parser.add_argument('--input',required=True,type=Path)
    args=parser.parse_args()
    offset,data=prepare_input(args.input,args.mode,args.offset)
    print(json.dumps(write_patch(offset,data,args.port,args.backup_dir),indent=2))
