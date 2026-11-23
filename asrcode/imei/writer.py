"""MRD IMEI transaction: persist evidence, verify storage and restore PROD mode."""
import re

def complete_imei(value,template='000000000000000'):
    value=str(value).strip()
    if not re.fullmatch(r'[0-9]{1,15}',value):raise ValueError('IMEI或前缀须为1至15位半角数字')
    digits=value[:14] if len(value)==15 else (value+template[len(value):14]).ljust(14,'0')
    total=sum((int(c)*2//10+int(c)*2%10) if i%2 else int(c) for i,c in enumerate(digits))
    expected=digits+str((-total)%10)
    if len(value)==15 and value!=expected:
        raise ValueError(f'IMEI校验位错误：末位应为{expected[-1]}；对应完整值为{expected}。未发送修改指令。')
    return expected

def mrd_value(reply):
    values=set(re.findall(r'^\s*\*MRD_IMEI:\s*"?([0-9]{15})"?\s*$',reply,re.M))
    if len(values)!=1:raise ValueError('无法唯一核对MRD中的原IMEI，未删除或覆盖记录')
    return values.pop()

def replace_imei(wire,target,send,query,check_cancel=lambda:None,log=lambda text:None,save=lambda report:None,force=False):
    if not re.fullmatch(r'[0-9]{15}',str(target)):raise ValueError('IMEI必须为15位半角数字')
    target=complete_imei(target)
    report={'success':False,'imei':target,'original_imei':None,'command_accepted':False,
            'storage_verified':False,'runtime_verified':False,'reboot_verified':False,
            'mode_restored':True,'writes_executed':False,'events':[]}
    prior_mode=None;changed_mode=False;deleted=False;responsive=True
    def command(text,cancellable=True):
        nonlocal responsive
        log('发送：'+text)
        result=send(wire,text,check_cancel=check_cancel if cancellable else lambda:None)
        raw=result.get('reply',b'').decode('utf-8',errors='replace')
        report['events'].append({'command':text,'success':bool(result.get('success')),'reply':raw})
        save(report);log('应答：'+raw.strip())
        if not result.get('terminated',result.get('success',False)):
            responsive=False
            raise RuntimeError('AT响应不完整，写入结果未知；停止继续发送修改指令，请重新连接后读取核对')
        return result,raw
    try:
        check_cancel()
        current=query(wire,send,check_cancel=check_cancel,log=log)
        if not current.get('success'):raise RuntimeError('无法读取当前IMEI，未执行修改')
        original=report['original_imei']=current['imei'];save(report)
        if original==target and not force:
            report.update(success=True,unchanged=True,runtime_verified=True)
            log('当前IMEI与目标一致，无需修改，未发送写号或解除保护指令。')
            return report
        result,reply=command('AT*PROD?')
        match=re.search(r'\*PROD:\s*([01])\b',reply)
        if not result.get('success') or not match:raise RuntimeError('无法确认原工厂模式，未执行修改')
        prior_mode=int(match[1]);report['original_prod_mode']=prior_mode
        result,reply=command('AT*MRD_IMEI?')
        if not result.get('success') or mrd_value(reply)!=original:
            raise RuntimeError('MRD记录与当前IMEI不一致，未执行修改')
        if prior_mode==0:
            changed_mode=True;report['mode_restored']=False
            result,_=command('AT*PROD=1')
            if not result.get('success'):raise RuntimeError('进入工厂模式失败，未执行写入')
        check_cancel()
        # From the first write to readback/rollback, defer stop to finish the transaction.
        report['writes_executed']=True;save(report)
        write=f'AT*MRD_IMEI=W,0,01JAN1970,{target}'
        result,_=command('AT+FLASHBP=0',False)
        if not result.get('success'):raise RuntimeError('FLASH解锁失败，未删除IMEI')
        result,_=command('AT*MRD_IMEI=D',False)
        if not result.get('success'):raise RuntimeError('删除旧IMEI失败，未继续写入')
        deleted=True
        result,reply=command(write,False)
        if not result.get('success'):raise RuntimeError('MRD重建失败，尝试恢复原IMEI')
        report['command_accepted']=True
        result,reply=command('AT*MRD_IMEI?',False)
        if not result.get('success') or mrd_value(reply)!=target:
            raise RuntimeError('写入应答成功，但MRD回读与目标不一致')
        report['storage_verified']=True
    except Exception as exc:
        report['error']=str(exc)
        if (deleted or report['command_accepted']) and not report['storage_verified'] and responsive:
            try:
                result,reply=command('AT*MRD_IMEI?',False)
                try:stored=mrd_value(reply) if result.get('success') else None
                except ValueError:stored=None
                if stored and stored!=report['original_imei']:
                    result,_=command('AT*MRD_IMEI=D',False)
                    if not result.get('success'):raise RuntimeError('回滚时无法删除异常记录')
                result,_=command(f"AT*MRD_IMEI=W,0,01JAN1970,{report['original_imei']}",False)
                result,reply=command('AT*MRD_IMEI?',False)
                report['rollback_verified']=bool(result.get('success') and mrd_value(reply)==report['original_imei'])
            except Exception as rollback_error:report['rollback_error']=str(rollback_error)
    finally:
        if changed_mode:
            try:
                result,_=command('AT*PROD=0',False)
                result,reply=command('AT*PROD?',False)
                report['mode_restored']=bool(result.get('success') and re.search(r'\*PROD:\s*0\b',reply))
            except Exception as cleanup_error:report['cleanup_error']=str(cleanup_error)
        save(report)
    if report['storage_verified'] and report['mode_restored']:
        try:
            runtime=query(wire,send,check_cancel=lambda:None,log=log)
            report['runtime_imei']=runtime.get('imei')
            report['runtime_verified']=runtime.get('success',False) and runtime.get('imei')==target
            report['success']=report['runtime_verified']
            if not report['success']:report['error']='MRD已写入并核对，运行时IMEI尚未匹配；需重启后重新读取，未自动重启'
        except Exception as exc:report['error']='MRD已核对，运行时回读失败：'+str(exc)
    if not report['mode_restored']:
        report['success']=False;report['error']='工厂模式未确认恢复，请检查设备；'+report.get('error','')
    save(report)
    return report
