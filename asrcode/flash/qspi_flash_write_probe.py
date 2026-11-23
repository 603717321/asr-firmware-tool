"""Bounded live write/erase experiment: only the saved blank last 4 KiB sector."""
import argparse
import hashlib
import json
import struct
import time
from asrcode.flash.qspi_flash_probe import Qspi, ROOT

SECTOR=0x7ff000
TARGET=0x7fff00
MARKER=b'ASRW'


class WritableQspi(Qspi):
    def flash_ready(self):
        for _ in range(100):
            status=self.read_ip(2,0x80000000,1)[0]
            if not status&1:
                return status
            time.sleep(.01)
        raise TimeoutError('Flash WIP did not clear')

    def issue(self,seq,offset=0,data=b''):
        self.wait_idle()
        self.write(0x16c,0x100)
        self.write(0x100,0x80000000+offset)
        self.write(0x160,self.read(0x160))
        if data:
            self.write(0,self.read(0)|0x800)
            padded=data+b'\x00'*(-len(data)%16)
            for i in range(0,len(padded),4):
                self.write(0x154,struct.unpack_from('<I',padded,i)[0])
        self.write(8,(seq<<24)|len(data))
        self.wait_idle()
        flags=self.read(0x160)
        self.events.append({'issued_seq':seq,'offset':hex(offset),
                            'data':data.hex(),'flags':hex(flags)})
        if flags&0xd0:
            raise RuntimeError(f'QSPI command error: {flags:#x}')

    def write_enable(self):
        self.flash_ready()
        if self.read(0x320)!=0x406 or self.read(0x324)!=0:
            raise RuntimeError('Existing WREN LUT changed')
        self.issue(1)
        status=self.flash_ready()
        if not status&2:
            raise RuntimeError(f'WEL not set: {status:#x}')

    def program(self,offset,data):
        if not SECTOR<=offset<SECTOR+4096 or offset+len(data)>SECTOR+4096:
            raise ValueError('Probe limited to backed-up last sector')
        if not 1<=len(data)<=128 or offset//256!=(offset+len(data)-1)//256:
            raise ValueError('Program must fit one page and 128-byte FIFO')
        if self.read(0x370)!=0x08180402 or self.read(0x374)!=0x2000:
            raise RuntimeError('Existing PP LUT changed')
        self.write_enable()
        self.issue(6,offset,data)
        self.flash_ready()
        actual=self.read_ip(3,0x80000000+offset,len(data))
        if actual!=data:
            raise RuntimeError(f'Program verify failed: {actual.hex()} != {data.hex()}')

    def restore_blank_sector(self):
        backup=(ROOT/'write_probe_sector_7ff000.original.bin').read_bytes()
        if backup!=b'\xff'*4096:
            raise RuntimeError('Probe backup is not a blank 4 KiB sector')
        # Use unused sequence 15; never modify the live AHB read sequence 0.
        saved=[self.read(0x400+i*4) for i in range(4)]
        lock=self.read(0x304)
        try:
            self.wait_idle()
            self.write(0x300,0x5af05af0)
            self.write(0x304,2)
            for i,value in enumerate([0x08180420,0,0,0]):
                self.write(0x400+i*4,value)
            if self.read(0x400)!=0x08180420:
                raise RuntimeError('Sector erase LUT failed to install')
            self.write_enable()
            self.issue(15,SECTOR)
            self.flash_ready()
            actual=b''.join(self.read_ip(3,0x80000000+SECTOR+i,128)
                            for i in range(0,4096,128))
            if actual!=backup:
                raise RuntimeError('Sector restore verification failed')
        finally:
            self.write(0x300,0x5af05af0)
            self.write(0x304,2)
            for i,value in enumerate(saved):
                self.write(0x400+i*4,value)
            self.write(0x300,0x5af05af0)
            self.write(0x304,lock)


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('action',choices=['program','verify','restore'])
    args=ap.parse_args()
    q=WritableQspi()
    result={'action':args.action,'offset':hex(TARGET),'timestamp':time.time()}
    try:
        if args.action=='program':
            old=q.read_ip(3,0x80000000+TARGET,16)
            if old!=b'\xff'*16:
                raise RuntimeError('Target is not blank')
            q.program(TARGET,MARKER)
        elif args.action=='verify':
            actual=q.read_ip(3,0x80000000+TARGET,16)
            result['actual']=actual.hex()
            if actual!=MARKER+b'\xff'*12:
                raise RuntimeError('Marker mismatch')
        else:
            q.restore_blank_sector()
        result['success']=True
        print(json.dumps(result),flush=True)
    except Exception as exc:
        result.update(success=False,error=repr(exc))
        raise
    finally:
        (ROOT/f'write_probe_{args.action}_{time.time_ns()}.json').write_text(
            json.dumps(result,indent=2))
        q.close()


if __name__=='__main__':
    main()
