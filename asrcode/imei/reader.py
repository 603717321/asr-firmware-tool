"""Read-only IMEI query, accepting only complete successful AT responses."""
import re

def parse_imei(reply):
    if isinstance(reply,bytes):reply=reply.decode('ascii',errors='replace')
    values=set()
    for line in reply.splitlines():
        match=re.fullmatch(r'\s*(?:(?:\+CGSN|\+GSN|IMEI)\s*:\s*)?"?(\d{15})"?\s*',line)
        if match:values.add(match[1])
    if len(values)!=1:raise ValueError('响应中未找到唯一的15位IMEI，输入框未更改。')
    return values.pop()

def query_imei(wire,send,check_cancel=lambda:None,log=lambda text:None):
    replies=[]
    for command in ('AT+CGSN','AT+CGSN=1','AT+GSN'):
        log('读取IMEI，发送：'+command)
        result=send(wire,command,check_cancel=check_cancel)
        raw=result.get('reply',b'');text=raw.decode('utf-8',errors='replace')
        replies.append(text);log('设备应答：'+text.strip())
        if result.get('success'):
            try:imei=parse_imei(text)
            except ValueError:continue
            return {'success':True,'imei':imei,'reply':'\n'.join(replies),'command':command,'read_imei':True}
        if not result.get('terminated'):break
    return {'success':False,'read_imei':True,'reply':'\n'.join(replies),
            'error':'未读取到有效IMEI，请检查AT端口或设备是否支持查询。输入框未更改。'}
