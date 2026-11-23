"""One manual AT request with bounded response capture; no setup commands."""
import re
import time


def at_command(value):
    command=str(value).strip()
    if not command or any(c in command for c in '\r\n\x00'):
        raise ValueError('请输入一条单行AT指令')
    if not command.upper().startswith('AT') or len(command)>2048:
        raise ValueError('AT指令须以AT开头，长度不超过2048字符')
    try:command.encode('ascii')
    except UnicodeEncodeError:raise ValueError('AT指令须使用ASCII字符') from None
    return command


def send_at(wire,value,timeout=5,check_cancel=lambda:None,limit=65536):
    command=at_command(value)
    check_cancel()
    wire.write((command+'\r').encode('ascii'))
    response=bytearray();deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        check_cancel()
        data=wire.read(min(max(1,wire.in_waiting),limit-len(response)))
        response.extend(data)
        terminal=re.search(rb'(?:^|\r\n)(OK|ERROR(?::[^\r\n]*)?|\+(?:CME|CMS) ERROR:[^\r\n]*)\r\n',response)
        if terminal:
            return {'reply':bytes(response),'success':terminal[1]==b'OK','terminated':True,'timed_out':False}
        if len(response)>=limit:
            return {'reply':bytes(response),'success':False,'terminated':False,'timed_out':False,'limit_reached':True}
    return {'reply':bytes(response),'success':False,'terminated':False,'timed_out':True}
