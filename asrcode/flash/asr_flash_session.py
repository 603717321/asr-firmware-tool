"""State-verified temporary cellular and Flash protection settings."""
import re
class SettingSession:
    def __init__(self,wire,exchange=None):
        if exchange is None:
            from asrcode.flash.at_flash_backup import exchange
        self.exchange=exchange;self.wire=wire;self.changes=[];self.events=[]
    def command(self,command):
        reply=self.exchange(self.wire,command+'\r')
        if not reply.endswith(b'\r\nOK\r\n') or b'ERROR' in reply:raise RuntimeError(command+' 被设备拒绝：'+repr(reply[-160:]))
        return reply
    def query(self,name):
        reply=self.command('AT'+name+'?')
        pattern=re.escape(name.encode())+rb':[^\r\n]*'
        match=re.search(pattern,reply,re.I)
        if not match:raise RuntimeError('无法确认 '+name+' 原状态：'+repr(reply[-160:]))
        # FLASHBP may include the vendor Flash name before the numeric setting.
        value=re.search(rb'(?:[:,]\s*)(\d+)\s*$',match.group())
        if not value:raise RuntimeError('无法解析 '+name+' 状态')
        return int(value[1])
    def set(self,name,value,original=None,force=False):
        original=self.query(name) if original is None else original
        if original==value and not force:return
        # Track before sending: a command may execute even if its ACK is lost.
        if not any(item[0]==name for item in self.changes):self.changes.append((name,original))
        self.command('AT'+name+'='+str(value))
        actual=self.query(name)
        if actual!=value:raise RuntimeError(name+' 修改未生效，回读='+str(actual))
        self.events.append({'setting':name,'before':original,'after':value})
    def close(self):
        errors=[]
        while self.changes:
            name,value=self.changes.pop()
            try:
                self.command('AT'+name+'='+str(value))
                if self.query(name)!=value:raise RuntimeError('状态回读不一致')
                self.events.append({'restored':name,'value':value})
                print('已恢复 '+name+'='+str(value),flush=True)
            except Exception as exc:errors.append(name+': '+str(exc))
        if errors:raise RuntimeError('设备状态恢复失败：'+'；'.join(errors))

class CellularSession(SettingSession):
    def start(self):
        original=self.query('+CFUN')
        self.set('+CFUN',0,original)
        print('蜂窝已暂停（CFUN=0，已回读确认）；原状态 CFUN='+str(original),flush=True)

class FlashProtectionSession(SettingSession):
    def start(self,status,complement_status=None):
        self.status=status;self.before=status()
        self.complement_status=complement_status
        self.before2=complement_status() if complement_status else None
        self.changes.append(('+FLASHBP',1))
        self.command('AT+FLASHBP=0')
        # The queried FLASHBP value is a driver mode, not the physical BP bits.
        import time
        for _ in range(10):
            after=status()
            after2=complement_status() if complement_status else None
            if not self._protected(after,after2):break
            time.sleep(.1)
        self.events.append({'flash_status_before':hex(self.before),'flash_status_after':hex(after),
                            'status2_before':hex(self.before2) if self.before2 is not None else None,
                            'status2_after':hex(after2) if after2 is not None else None,
                            'protection_decode':'BP+CMP' if complement_status else 'BP'})
        if self._protected(after,after2):raise RuntimeError('AT解锁返回成功，但物理保护仍启用：SR1='+hex(after)+' SR2='+str(after2)+'；未执行擦写')
        print('Flash写保护已解除（'+('BP/CMP互补保护' if complement_status else 'BP位')+'已回读确认）',flush=True)
    @staticmethod
    def _protected(status,status2=None):
        bp=status&0x1c
        if status2 is not None and status2&0x40:
            return bp!=0x1c
        return bp!=0
    def close(self):
        errors=[]
        remaining=[]
        while self.changes:
            name,value=self.changes.pop()
            if name=='+FLASHBP':
                try:
                    self.command('AT+FLASHBP='+str(value))
                    self.events.append({'restored':name,'value':value})
                    print('已恢复 '+name+'='+str(value),flush=True)
                except Exception as exc:errors.append(name+': '+str(exc))
            else:
                remaining.append((name,value))
        self.changes=remaining
        super().close()
        if hasattr(self,'before'):
            actual=self.status()
            actual2=self.complement_status() if self.complement_status is not None else None
            was_prot=self._protected(self.before,self.before2)
            now_prot=self._protected(actual,actual2)
            if was_prot and not now_prot:
                raise RuntimeError('Flash写保护未恢复：'+hex(self.before)+' -> '+hex(actual))
            if self.complement_status is not None:
                if actual2&0x40!=self.before2&0x40:raise RuntimeError('Flash CMP保护恢复回读不一致')
