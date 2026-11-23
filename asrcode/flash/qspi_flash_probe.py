"""Device-specific QSPI register probe, grounded in MF808 V81 driver disassembly."""
import json
import struct
import time
from pathlib import Path
import serial
from asrcode.flash.at_flash_backup import exchange, read_words, synchronize

BASE = 0xd420b000
ROOT = Path(__file__).resolve().parent


class Qspi:
    def __init__(self, port="COM10",baudrate=115200,records_dir=None):
        from asrcode.flash.asr_io_settings import baudrate_value
        self.records_dir=Path(records_dir) if records_dir is not None else ROOT/'读刷工具记录'/'底层记录'
        self.serial = serial.Serial(port,baudrate_value(baudrate),timeout=.001,write_timeout=3)
        try:
            synchronize(self.serial)
            self.events = []
            self.saved = {off:self.read(off) for off in (0,0x100,0x110,0x164)}
            if self.saved[0x164] != 0:
                raise RuntimeError('QSPI interrupts enabled; refusing polling probe')
        except Exception:
            self.serial.close()
            raise

    def read(self, offset):
        return struct.unpack('<I',read_words(self.serial,BASE+offset,1))[0]

    def write(self, offset, value):
        reply = exchange(self.serial,f'AT*REGRW=w,{BASE+offset:08x},{value:08x}\r')
        self.events.append({'write':hex(BASE+offset),'value':hex(value),'reply':reply.decode(errors='replace')})
        if not reply.endswith(b'\r\nOK\r\n'):
            raise RuntimeError(reply)

    def wait_idle(self):
        for _ in range(100):
            if not self.read(0x15c)&1:
                return
            time.sleep(.01)
        raise TimeoutError('QSPI remains busy')

    def read_ip(self, seq, address, length):
        for attempt in range(3):
            try:
                return self._read_ip_once(seq,address,length)
            except RuntimeError as exc:
                self.events.append({'read_retry':attempt+1,'error':repr(exc)})
                if attempt==2:
                    raise
                time.sleep(.1)
                synchronize(self.serial)

    def _read_ip_once(self, seq, address, length):
        if seq not in (2,3,*getattr(self,'profile',{}).get('sequences',{}).values()) or not 1<=length<=128:
            raise ValueError('Only existing status/read LUT sequences permitted')
        self.wait_idle()
        self.write(0,self.read(0)|0x400)
        self.write(0x16c,0x100)
        self.write(0x100,address)
        self.write(0x110,0x100|((length+3)//4-1))
        self.write(0x160,self.read(0x160))
        self.write(8,(seq<<24)|length)
        self.wait_idle()
        for _ in range(50):
            flags=self.read(0x160)
            if flags & 1:
                break
            time.sleep(0.005)
        words=(length+3)//4
        data=read_words(self.serial,BASE+0x200,words)[:length]
        self.events.append({'seq':seq,'address':hex(address),'length':length,
                            'flags':hex(flags),'data':data.hex()})
        if flags&0xd0:
            raise RuntimeError(f'QSPI command error {flags:#x}')
        return data

    def close(self):
        try:
            self.wait_idle()
            for off in (0x100,0x110,0x164,0):
                self.write(off,self.saved[off])
        finally:
            self.serial.close()
            folder=getattr(self,'records_dir',ROOT/'读刷工具记录'/'底层记录')
            folder.mkdir(parents=True,exist_ok=True)
            (folder/f'qspi_read_probe_{time.time_ns()}.json').write_text(
                json.dumps(self.events,indent=2),encoding='utf-8')


if __name__=='__main__':
    q=Qspi()
    try:
        status=q.read_ip(2,0x80000000,1)
        data=q.read_ip(3,0x80000000,16)
        reference=read_words(q.serial,0x80000000,4)
        print(json.dumps({'status':status.hex(),'ip_read':data.hex(),
                          'mapped_read':reference.hex(),'equal':data==reference}),flush=True)
        if data!=reference:
            raise RuntimeError('IP read does not match mapped Flash')
    finally:
        q.close()
