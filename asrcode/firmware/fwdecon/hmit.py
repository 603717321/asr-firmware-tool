#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""hmit.py —— HMIT 固件解析（不依赖硬编码偏移）

固件布局（实测 MF811_V52 / MF813_V60 两份，8MB）
======================================================================
  0x00       16B 头：00 04 03 00 "HMIT" ...
  0x38       第二级 "HMIT" 头
  0xFC 起    分区描述符，96B 一项：name(4,反序) + off + loadaddr + size
  0x40000    OSLO 主镜像（多个 LZMA-alone 段首尾相接）
  0x20000    identity  (fecace)
  0x30000    calib     (fecace)
  0x530000   www       (fecace, 0xC0000)
  0x5F0000   wifi_calib(fecace, 0x20000) ★与 www 相邻，改 www 时极易被推走

OSLO 段的坑
======================================================================
  * 段是 **FORMAT_RAW 无 EOS 标记** 的裸流。用 LZMADecompressor 等 eof
    会一路吃到文件尾 -> 必须靠「下一个 props 头」定界。
  * 头是 props(5B: 5d 00 00 10 00) + dict(u32) + usize(u64)。
    **usize 必须写真值**；Python 的 FORMAT_ALONE 会写成全 FF，
    bootloader 读不到长度就变砖。
  * 段之间不是 0x1000 对齐的，props 头位置就是段起点。

fecace 区
======================================================================
  头 fe ca fe ca + adler32(u32) + 0x1019，随后 8+128 字节一项
  （flag/name），条目链末尾 4B 是 da da da da。
"""
import lzma
import struct
import zlib

PROP = bytes([0x5D, 0x00, 0x00, 0x10, 0x00])
FECACE = b"\xfe\xca\xfe\xca"
TAIL_MARK = b"\xda\xda\xda\xda"
HDR, NAME, HEAD = 8, 128, 20
# 真实 OSLO 段「流长 + padding」的上限：实测最大流长 ≈ 0x90000，
# 超过这个间隔就认为是两个不相干的区（www / wifi_calib 里的 LZMA）
GAP_MAX = 0x94000


class Seg(object):
    def __init__(self, off, end, usize, dic):
        self.off = off            # 相对固件头
        self.end = end
        self.usize = usize
        self.dic = dic
        self.raw = None           # 解压后数据
        self.dirty = False

    @property
    def room(self):
        return self.end - self.off

    def __repr__(self):
        return "<Seg 0x%X-0x%X usize=%d%s>" % (
            self.off, self.end, self.usize, "*" if self.dirty else "")


class Firmware(object):
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.data = bytearray(f.read())
        self.segs = []
        self.oslo = None          # (off, size)
        self.regions = []
        self.err = None
        self._parse()

    # ---------------- OSLO 自动发现 ----------------
    def _find_oslo(self):
        # Use TIM image boundaries, never APNL or WIFI streams.
        d = self.data
        if len(d) < 56 or d[4:8] != b'HMIT':
            return None
        count = struct.unpack_from('<I', d, 44)[0]
        if not 1 <= count <= 64:
            return None
        for i in range(count):
            at = 56 + i * 96
            if d[at:at+4] == b'OLSO':
                off, size = struct.unpack_from('<I', d, at+8)[0], struct.unpack_from('<I', d, at+16)[0]
                break
        else:
            from .cpz_region import application_region
            region=application_region(d)
            if region is None:return None
            off,size,heads=region
            self.tim_oslo=(off,size)
            self.application_region_source='QSPI header + CPZ records + verified decompression'
            return heads
        if off + size > len(d):
            return None
        self.tim_oslo = (off, size)
        heads = []
        for at in range(off, off + size - 13):
            if d[at] != 0x5d:
                continue
            dic = struct.unpack_from('<I', d, at+1)[0]
            us = struct.unpack_from('<Q', d, at+5)[0]
            if not 4096 <= dic <= (1 << 26) or dic & (dic-1) or not 0 < us <= (16 << 20):
                continue
            try:
                dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW,
                    filters=[{'id':lzma.FILTER_LZMA1,'dict_size':dic}])
                raw = dec.decompress(bytes(d[at+13:off+size]), max_length=us)
                if len(raw) == us:
                    heads.append(at)
            except lzma.LZMAError:
                pass
        return heads or None

    def _parse(self):
        heads = self._find_oslo()
        if not heads:
            self.err = "未发现 OSLO 镜像区（没找到可解压的 LZMA 段）"
            return
        self.regions = self._find_regions()
        # 最后一段的边界：不能越过下一个 fecace 区（wifi_calib 就在 www 之后）
        tail_limit = sum(self.tim_oslo)
        for off, _end, _ok in self.regions:
            if off > heads[-1]:
                tail_limit = min(tail_limit, off)
                break
        for k, h in enumerate(heads):
            if k + 1 < len(heads):
                end = heads[k + 1]
            else:
                end = min(tail_limit, h + 0x420000)
            dic = struct.unpack_from("<I", self.data, h + 1)[0]
            us = struct.unpack_from("<Q", self.data, h + 5)[0]
            s = Seg(h, end, us, dic)
            s.raw = self._dec(s)
            self.segs.append(s)
        self.oslo = (heads[0], self.segs[-1].end - heads[0])
        bad = [hex(s.off) for s in self.segs if s.raw is None]
        if bad:
            self.err = "以下段解压失败: %s" % ", ".join(bad)

    def _dec(self, s):
        try:
            dec = lzma.LZMADecompressor(
                format=lzma.FORMAT_RAW,
                filters=[{"id": lzma.FILTER_LZMA1, "dict_size": s.dic}])
            out = dec.decompress(bytes(self.data[s.off + 13:s.end]),
                                 max_length=s.usize)
        except Exception:
            return None
        return bytes(out) if len(out) == s.usize else None

    # ---------------- fecace 区 ----------------
    def _find_regions(self):
        """返回 [(off, end, ok)] —— 用于确认改完 www 后下一区还在原位"""
        out = []
        d = self.data
        p = 0
        while True:
            i = d.find(FECACE, p)
            if i < 0:
                break
            end = self._chain_end(d, i + HEAD)
            if end:
                ad = struct.unpack_from("<I", d, i + 4)[0]
                ok = (zlib.adler32(bytes(d[i + 8:end])) & 0xFFFFFFFF) == ad
                # 数据里偶然出现的 fe ca fe ca 会产生大量假区，
                # 只有 adler32 自洽的才是真区
                if ok:
                    out.append((i, end, ok))
            p = i + 4
        return out

    @staticmethod
    def _chain_end(d, p):
        while p + HDR + NAME <= len(d):
            if d[p + 2] != 0xFE or d[p + 3] != 0xCA:
                break
            size = struct.unpack_from("<I", d, p + 4)[0] & 0x00FFFFFF
            nm = d[p + HDR:p + HDR + NAME].split(b"\x00")[0]
            if not nm:
                break
            p = p + HDR + NAME + size
        return p

    @property
    def main_seg(self):
        """主应用段 = 解压后最大的段"""
        if not self.segs:
            return None
        return max(self.segs, key=lambda s: s.usize)


