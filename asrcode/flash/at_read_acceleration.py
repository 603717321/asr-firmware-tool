"""Session-scoped echo suppression and capability-validated binary Flash reads."""
import re
import time

from asrcode.flash.operation_control import check_stop,OperationCancelled


class BinaryFlashReader:
    def __init__(self,wire,stop_file=None):
        self.wire=wire
        self.stop_file=stop_file
        self.commands=0

    def read(self,address,length):
        offset=address-0x80000000
        if offset<0 or offset+length>0x100000000 or not 1<=length<=4096:
            raise ValueError('Invalid binary Flash read range')
        check_stop(self.stop_file)
        # Firmware consumes decimal FLASH OFFSETS, not mapped CPU addresses.
        self.wire.write(f'AT*READFLASH={offset},{length}\r'.encode('ascii'))
        self.commands+=1
        raw=bytearray();required=length+6;deadline=time.monotonic()+4
        while len(raw)<required and time.monotonic()<deadline:
            check_stop(self.stop_file)
            raw.extend(self.wire.read(min(required-len(raw),max(4096,self.wire.in_waiting))))
        if len(raw)!=required or raw[length:]!=b'\r\nOK\r\n':
            raise RuntimeError(f'Binary Flash frame length/footer mismatch at {offset:#x}: {len(raw)}/{required}; prefix={raw[:16].hex()}, tail={raw[-16:].hex()}')
        # Never search for OK/ERROR inside binary payload: both can be data.
        return bytes(raw[:length])


class ReadAcceleration:
    def __init__(self,wire,base,length,stop_file=None):
        self.wire=wire;self.base=base;self.length=length;self.stop_file=stop_file
        self.restore_echo=False;self.native=None;self.echo_disabled=False
        self.probe_error=''

    def start(self):
        from asrcode.flash.at_flash_backup import exchange,read_addresses,synchronize
        if not all(hasattr(self.wire,name) for name in ('read','write','in_waiting')):return
        reply=exchange(self.wire,'AT\r')
        if reply.lstrip().upper().startswith(b'AT\r'):
            self.restore_echo=True
            reply=exchange(self.wire,'ATE0\r')
            if not reply.endswith(b'\r\nOK\r\n') or b'ERROR' in reply:
                self.probe_error='ATE0 rejected';return
        # Confirm echo really is off before interpreting a raw binary frame.
        reply=exchange(self.wire,'AT\r')
        if reply.lstrip().upper().startswith(b'AT\r') or reply.strip()!=b'OK':
            self.probe_error='AT echo state unconfirmed';return
        self.echo_disabled=True
        check_stop(self.stop_file)
        reply=exchange(self.wire,'AT*READFLASH=?\r')
        # Help text varies between firmware builds. Actual read-only data
        # comparison, rather than a help-string signature, decides support.
        # Even ERROR on the help form does not prove the read form is absent.
        try:
            native=BinaryFlashReader(self.wire,self.stop_file)
            # Compare distinct offsets using two independent observations through
            # each transport. No device model/version rules and no Flash writes.
            points=sorted({0,self.base-0x80000000,
                           self.base-0x80000000+max(0,self.length-64)})
            observed=[]
            for offset in points:
                if offset<0 or offset%4:raise ValueError('Unaligned capability sample')
                size=min(64,self.length)
                if size%4:raise ValueError('Unaligned capability length')
                check_stop(self.stop_file)
                address=0x80000000+offset
                mapped=[read_addresses(self.wire,range(address,address+size,4)) for _ in range(2)]
                binary=[native.read(address,size) for _ in range(2)]
                if not mapped[0]==mapped[1]==binary[0]==binary[1]:
                    raise ValueError(f'Binary/mapped capability samples disagree at {offset:#x}')
                observed.append(binary[0])
            if len(set(observed))<2:
                # If target points returned uniform data (e.g. padding/erased flash),
                # sample distinct auxiliary offsets to confirm address responsiveness.
                for aux in (0x20, 0x1000, 0x40000):
                    if aux not in points:
                        check_stop(self.stop_file)
                        try:
                            aux_map = read_addresses(self.wire, range(0x80000000+aux, 0x80000000+aux+64, 4))
                            aux_bin = native.read(0x80000000+aux, 64)
                            if aux_map == aux_bin:
                                observed.append(aux_bin)
                                if len(set(observed)) >= 2:
                                    break
                        except Exception:
                            pass
                # As long as all binary reads matched mapped AHB reads identically,
                # do not fail if the entire physical Flash contains uniform bytes (e.g. blank Flash).
                if len(set(observed)) < 2 and not (observed and observed[0] == mapped[0]):
                    raise ValueError('Capability samples lack distinct offset data')
            if self.length>=4096:
                if native.read(self.base,4096)!=native.read(self.base,4096):
                    raise ValueError('4KiB binary capability pair disagrees')
            self.native=native
        except OperationCancelled:raise
        except (RuntimeError,ValueError,OSError) as exc:
            self.probe_error=str(exc)
            synchronize(self.wire)

    def close(self):
        if self.restore_echo:
            from asrcode.flash.at_flash_backup import exchange
            self.restore_echo=False
            reply=exchange(self.wire,'ATE1\r')
            if not reply.endswith(b'\r\nOK\r\n') or b'ERROR' in reply:
                raise RuntimeError('Cannot restore original AT echo')
