"""Generate a fresh Luhn-valid value while preserving an entered prefix."""
import re
import secrets
_previous={}
def random_imei(prefix):
    prefix=str(prefix).strip()
    if not re.fullmatch(r'[0-9]{0,13}',prefix):
        raise ValueError('随机补全请输入0至13位数字前缀；14位已没有可随机补全的数据位。完整15位请关闭自动补全。')
    count=14-len(prefix);space=10**count
    last=_previous.get(prefix)
    value=secrets.randbelow(space if last is None else space-1)
    if last is not None and value>=last:value+=1
    _previous[prefix]=value
    digits=prefix+str(value).zfill(count)
    total=sum((int(c)*2//10+int(c)*2%10) if i%2 else int(c) for i,c in enumerate(digits))
    return digits+str((-total)%10)
