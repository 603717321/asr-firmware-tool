"""Identify supported QSPI NOR command capabilities, without model/version rules."""
import struct

BASE=0xd420b000


def complementary_protection(jedec_id,parameters):
    """Positive status-layout identification; no speculative register writes.

    Dosilicon DS25M64E datasheet rev03/06: SR2 bit6 is CMP. BP=000
    with CMP=1 protects all; BP=111 with CMP=1 protects none.
    """
    return (bytes(jedec_id)==bytes.fromhex('e54117') and
            parameters.get('source')=='SFDP BFPT' and
            parameters.get('capacity')==0x800000 and
            parameters.get('erase_opcode')==0x20)


def discover_profile(read):
    words=struct.unpack('<64I',read(BASE+0x310,64))
    entries=[tuple(words[i:i+4]) for i in range(0,64,4)]
    expected={
        'wren':lambda v:v[0]==0x406 and v[1] in (0,0x2000,0x2400) and v[2:]==(0,0),
        'status':lambda v:v[0]==0x1c000405 and v[1] in (0x2000,0x2400) and v[2:]==(0,0),
        'read':lambda v:v[0]==0x0818040b and v[1]==0x1c000c08 and v[2] in (0x2000,0x2400) and v[3]==0,
        'program':lambda v:v[0]==0x08180402 and v[1] in (0,0x2000,0x2400) and v[2:]==(0,0),
    }
    sequences={}
    for name,predicate in expected.items():
        matches=[i for i,value in enumerate(entries) if predicate(value)]
        if not matches:raise ValueError('Unsupported QSPI NOR command capability: '+name)
        sequences[name]=matches[0]
    if entries[15]!=(0,0,0,0):raise ValueError('No reserved empty LUT slot 15 for erase/JEDEC commands')
    if struct.unpack('<I',read(BASE+0x164,1))[0]!=0:
        raise ValueError('QSPI interrupts enabled; polling access unsupported')
    return {'controller':'fsl_qspi_nor','base':BASE,'sequences':sequences,
            'lut':{name:list(entries[index]) for name,index in sequences.items()}}


def expected_registers(profile,names=None):
    result={}
    for name,index in profile['sequences'].items():
        if names is None or name in names:
            result.update({0x310+index*16+i*4:value for i,value in enumerate(profile['lut'][name])})
    return result


def parse_sfdp(header,read):
    if header[:4]!=b'SFDP' or len(header)<8:raise ValueError('NOR SFDP signature missing')
    for index in range(header[6]+1):
        at=8+index*8
        if at+8>len(header):raise ValueError('SFDP parameter header truncated')
        row=header[at:at+8]
        if row[0]!=0 or row[7]!=255:continue
        length=row[3]*4;offset=int.from_bytes(row[4:7],'little')
        if not 36<=length<=128:raise ValueError('Unsupported SFDP basic parameter length')
        table=read(offset,length)
        if len(table)!=length:raise ValueError('SFDP basic parameters truncated')
        density=struct.unpack_from('<I',table,4)[0]
        bits=(1<<(density&0x7fffffff)) if density&0x80000000 and (density&0x7fffffff)<32 else density+1
        capacity=bits//8
        erases=[(table[at],table[at+1]) for at in (28,30,32,34)]
        if (12,0x20) not in erases:raise ValueError('SFDP does not advertise 4 KiB erase opcode 20h')
        if capacity<=0 or capacity>0x1000000:raise ValueError('NOR capacity requires unsupported address mode')
        if len(table)<44:raise ValueError('SFDP page geometry missing')
        page_size=1<<((struct.unpack_from('<I',table,40)[0]>>4)&15)
        if page_size<256:raise ValueError('Unsupported NOR page geometry')
        return {'capacity':capacity,'erase_size':4096,'erase_opcode':0x20,'page_size':page_size,'source':'SFDP BFPT'}
    raise ValueError('SFDP basic parameter table missing')
