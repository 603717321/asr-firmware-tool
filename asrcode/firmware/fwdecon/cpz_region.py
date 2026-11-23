"""Identify undeclared QSPI application regions using consistent CPZ load records."""
import lzma
import re
import struct

def application_region(data):
    records=[]
    for match in re.finditer(rb'RW_CPZ_[0-9A-Z][ -~]{0,7}\x00',data):
        at=match.start()
        if at+32>len(data):continue
        base,source,room,stored=struct.unpack_from('<4I',data,at+16)
        if not base or not room or room%4096 or room>0x400000:continue
        records.append((at,base,room,stored))
    groups=[]
    for record in records:
        if not groups or record[0]!=groups[-1][-1][0]+32:groups.append([])
        groups[-1].append(record)
    solutions=[]
    for group in groups:
        if len(group)<3:continue
        first=group[0];relative=first[3]&0xffffff
        for match in re.finditer(b'\x5d',data):
            origin=match.start()-relative
            if origin<0 or origin%4096 or origin+32>len(data):continue
            if data[origin+12:origin+16]!=b'QSPI' or data[origin+24:origin+28]!=b'RTIM':continue
            if not origin<=first[0]<match.start():continue
            heads=[];end=origin;valid=True
            for at,base,room,stored in group:
                start=origin+(stored&0xffffff)
                if start<end or start+room>len(data) or data[start]!=0x5d:valid=False;break
                dic=struct.unpack_from('<I',data,start+1)[0];usize=struct.unpack_from('<Q',data,start+5)[0]
                if not 4096<=dic<=1<<26 or dic&(dic-1) or not 0<usize<=16<<20:valid=False;break
                try:
                    decoder=lzma.LZMADecompressor(format=lzma.FORMAT_RAW,filters=[{'id':lzma.FILTER_LZMA1,'dict_size':dic}])
                    raw=decoder.decompress(bytes(data[start+13:start+room]),max_length=usize)
                except lzma.LZMAError:valid=False;break
                if len(raw)!=usize:valid=False;break
                heads.append(start);end=start+room
            if valid:solutions.append((origin,end-origin,heads))
    unique={(origin,size,tuple(heads)) for origin,size,heads in solutions}
    if len(unique)!=1:return None
    origin,size,heads=unique.pop()
    # Reject collisions with every declared TIM image, except a matching OSLO.
    if data[4:8]!=b'HMIT':return None
    count=struct.unpack_from('<I',data,44)[0]
    if not 1<=count<=64 or 56+96*count>len(data):return None
    for index in range(count):
        at=56+96*index;off=struct.unpack_from('<I',data,at+8)[0];length=struct.unpack_from('<I',data,at+16)[0]
        if length and max(origin,off)<min(origin+size,off+length):return None
    return origin,size,list(heads)
