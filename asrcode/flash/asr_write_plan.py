"""Complete read-before-write comparison, independent of erase/verify options."""
import hashlib

def scan_write_plan(read,offset,data,check,progress):
    first=offset//4096*4096;end=(offset+len(data)+4095)//4096*4096
    samples={};equal=[];different=[]
    for address in range(first,end,65536):
        check();size=min(65536,end-address);block=read(address,size)
        if len(block)!=size:raise RuntimeError('Comparison scan returned incomplete data; no write plan committed')
        for sector in range(address,address+size,4096):
            check();sample=bytes(block[sector-address:sector-address+4096]);samples[sector]=sample
            lo=max(offset,sector);hi=min(offset+len(data),sector+4096)
            (equal if sample[lo-sector:hi-sector]==data[lo-offset:hi-offset] else different).append(sector)
        progress(min(address+size,end)-first,end-first)
    return samples,{'equal_blocks':[hex(a) for a in equal],'different_blocks':[hex(a) for a in different],
                    'block_size':4096,'compared_bytes':len(data),
                    'snapshot_sha256':hashlib.sha256(b''.join(samples.values())).hexdigest()}
