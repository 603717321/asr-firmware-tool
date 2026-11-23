"""Negotiate write-command capacity using only an idle address register."""
def negotiate_write_batch(qspi,exchange,synchronize):
    saved=qspi.read(0x100);attempts=[]
    try:
        qspi.wait_idle()
        for count in (64,48,32,16,1):
            values=[0x80000000+i*4 for i in range(count)]
            command='AT'+';'.join(f'*REGRW=w,d420b100,{value:08x}' for value in values)+'\r'
            try:
                reply=exchange(qspi.serial,command)
                valid=reply.endswith(b'\r\nOK\r\n') and b'ERROR' not in reply and qspi.read(0x100)==values[-1]
                attempts.append({'count':count,'matched':valid})
                if valid:
                    qspi.batch_probe=attempts
                    print('写入指令批量已确认：'+str(count)+' 条/批',flush=True)
                    return count
            except (RuntimeError,OSError) as exc:attempts.append({'count':count,'error':str(exc)})
            synchronize(qspi.serial)
        raise RuntimeError('无法确认最小单条寄存器写入能力；未执行Flash擦写')
    finally:
        synchronize(qspi.serial);qspi.write(0x100,saved)
        if qspi.read(0x100)!=saved:raise RuntimeError('批量探测地址寄存器恢复失败')
