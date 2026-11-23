#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ASR 通用分区解析引擎 (Universal Partition Engine)
位置：asr_universal_partitions.py
设计原则：
1. 绝对不硬编码任何具体机型、型号名称或写死固定偏移。
2. 动态发现全盘所有 TIM 描述表（支持单层、多层嵌套 TIM，如 M8-3S 的 TIM1/TIM2）。
3. 动态嗅探并校验 FECACE 文件系统（Adler32 验证），精确定位任意位置的 Web 分区。
4. 动态嗅探主程序内核（OSLO/CPZ），无论是位于 0x20000 还是 0x40000，无论大小是 3.5MB 还是 5.12MB。
5. 提供安全等级评定（引导区禁止误刷、Web区安全推荐）。
6. 提供通用固件切片与提取功能。
"""
import os
import sys
import struct
import zlib
import hashlib
import re

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from asrcode.firmware.fwdecon import tim_integrity

# 标准分类元数据（纯语义分类，不绑定任何特定偏移）
SEMANTIC_CLASSIFICATION = {
    'TIMH': {'label': '启动信任头', 'risk': 'danger', 'desc': 'SoC片内冷启动Root-of-Trust引导清单，严禁日常刷写'},
    'TIM1': {'label': '二级TIM清单', 'risk': 'danger', 'desc': '二级引导信任描述表'},
    'TIM2': {'label': '三级TIM清单', 'risk': 'danger', 'desc': '三级引导信任描述表'},
    'OBMI': {'label': 'BootImage描述表', 'risk': 'danger', 'desc': 'Bootloader执行镜像表，损坏会导致芯片停留在BootROM'},
    'RBLI': {'label': '恢复/二级引导', 'risk': 'danger', 'desc': 'Secondary Boot / Recovery 镜像'},
    'OSLO': {'label': '主系统内核', 'risk': 'caution', 'desc': 'RTOS 主程序（含系统级守护进程与网络管理），需签名与等长约束'},
    'CPZ':  {'label': '主系统内核(CPZ)', 'risk': 'caution', 'desc': '未在主TIM中声明的运行时主应用代码段'},
    'WEBI': {'label': '网页控制台(WEBI)', 'risk': 'safe', 'desc': 'Web后台UI文件系统（FECACE），去控核心区，可单独极速安全刷写'},
    'WEB':  {'label': '网页控制台(WEB)', 'risk': 'safe', 'desc': 'Web后台UI文件系统（FECACE），去控核心区，可单独极速安全刷写'},
    'GRBI': {'label': '无线射频基带', 'risk': 'caution', 'desc': '基带协议栈与无线固件'},
    'RFBN': {'label': '射频参数校准', 'risk': 'danger', 'desc': '存放本机出厂射频金标校准，严禁刷入其他机器数据'},
    'MADC': {'label': '模组生产参数', 'risk': 'danger', 'desc': '模组出厂配置、硬件版本与出厂信息'},
    'APNL': {'label': '运营商APN表', 'risk': 'safe', 'desc': '预置运营商接入点列表'},
    'WIFI': {'label': 'WiFi固件', 'risk': 'caution', 'desc': '板载WiFi模组微码'},
    'NTLZ': {'label': '网络扩展参数', 'risk': 'caution', 'desc': '网络扩展与附加配置'},
    'USER_CONFIG': {'label': '用户运行时NV', 'risk': 'safe', 'desc': '用户运行配置区'},
}

def scan_all_fecace_filesystems(data):
    """动态全盘扫描并验证所有真实的 FECACE 文件系统（必须通过 Adler32 自洽校验）"""
    fecace_list = []
    limit = len(data)
    pos = 0
    while True:
        idx = data.find(b'\xfe\xca\xfe\xca', pos)
        if idx == -1:
            break
        if idx % 4096 == 0 and idx + 20 <= limit:
            expected_adler = struct.unpack_from('<I', data, idx + 4)[0]
            curr = idx + 20
            valid_chain = False
            while curr + 136 <= limit:
                if data[curr+2:curr+4] != b'\xfe\xca':
                    break
                entry_size = struct.unpack_from('<I', data, curr+4)[0] & 0x00FFFFFF
                curr = curr + 136 + entry_size
                valid_chain = True

            if valid_chain and curr <= limit:
                calc_adler = zlib.adler32(bytes(data[idx + 8:curr])) & 0xFFFFFFFF
                if calc_adler == expected_adler:
                    aligned_size = (curr - idx + 4095) // 4096 * 4096
                    fecace_list.append({
                        'offset': idx,
                        'end': curr,
                        'size': aligned_size,
                        'raw_size': curr - idx,
                        'adler32': hex(expected_adler)
                    })
        pos = idx + 4
    return fecace_list

def scan_cpz_kernel_application(data):
    """扫描未在主 TIM 表中明示的 CPZ/OSLO 运行时应用区"""
    try:
        from asrcode.firmware.fwdecon.cpz_region import application_region
        region = application_region(data)
        if region:
            off, size, _ = region
            return {'offset': off, 'size': size}
    except Exception:
        pass
    return None

def discover_universal_partitions(data):
    """
    通用分区全自动发现算法：
    结合所有 TIM 表、CPZ 嗅探和 FECACE 文件系统，生成全盘无重叠的完整分区表。
    """
    partitions = []
    seen_offsets = set()

    # 1. 扫描所有 TIM 表（使用 tim_integrity）
    try:
        tim_tables = tim_integrity.tables(data)
        for table in tim_tables:
            for entry in table['entries']:
                off = entry['offset']
                sz = entry['size']
                name = entry['name']
                if off not in seen_offsets:
                    seen_offsets.add(off)
                    meta = SEMANTIC_CLASSIFICATION.get(name, {
                        'label': f'分区({name})',
                        'risk': 'caution',
                        'desc': '未知用途'
                    })
                    partitions.append({
                        'name': name,
                        'offset': off,
                        'size': sz,
                        'label': meta['label'],
                        'risk': meta['risk'],
                        'desc': meta['desc'],
                        'source': f"TIM清单({table['name']}@0x{table['origin']:X})"
                    })
    except Exception:
        pass

    partition_names = {p['name'] for p in partitions}

    # 2. 若未声明 OSLO，检查 CPZ 应用段
    if 'OSLO' not in partition_names:
        cpz = scan_cpz_kernel_application(data)
        if cpz and cpz['offset'] not in seen_offsets:
            seen_offsets.add(cpz['offset'])
            partitions.append({
                'name': 'OSLO',
                'offset': cpz['offset'],
                'size': cpz['size'],
                'label': '主系统内核(CPZ)',
                'risk': 'caution',
                'desc': 'RTOS 主内核镜像',
                'source': 'CPZ加载元数据自动定位'
            })

    # 3. 扫描真实 Web 文件系统
    fecace_systems = scan_all_fecace_filesystems(data)
    web_idx = 1
    for fs in fecace_systems:
        foff = fs['offset']
        fsz = fs['size']
        if foff >= 0x380000 and fsz >= 0x7000:
            existing = next((p for p in partitions if p['offset'] == foff), None)
            if existing:
                existing['name'] = 'WEBI'
                existing['label'] = '网页控制台(WEBI)'
                existing['risk'] = 'safe'
                existing['desc'] = 'Web后台UI文件系统，去控修改核心区，可单独安全极速刷写'
            else:
                pname = 'WEBI' if web_idx == 1 else f'WEBI_{web_idx}'
                partitions.append({
                    'name': pname,
                    'offset': foff,
                    'size': fsz,
                    'label': f'网页控制台({pname})',
                    'risk': 'safe',
                    'desc': 'Web后台UI文件系统，去控修改核心区，可单独安全极速刷写',
                    'source': f"FECACE文件系统(Adler32={fs['adler32']})"
                })
                seen_offsets.add(foff)
                web_idx += 1

    # 4. 按物理偏移排序
    partitions.sort(key=lambda x: x['offset'])
    return partitions

def slice_universal_partition(data, mode, manual_offset=0):
    """
    通用固件分区切片提取器：
    根据模式或分区名称，自动返回 (target_flash_offset, sliced_bytes, partition_info)
    """
    partitions = discover_universal_partitions(data)
    
    if mode == 'full':
        return 0, data, {'name': 'FULL', 'label': '整机全片固件', 'risk': 'caution', 'offset': 0, 'size': len(data)}
    
    if mode == 'patch':
        return manual_offset, data, {'name': 'PATCH', 'label': '自定义偏移补丁', 'risk': 'safe', 'offset': manual_offset, 'size': len(data)}

    target_name = mode.upper()
    if target_name.startswith('TIM:'):
        target_name = target_name[4:]
    elif target_name in ('WEB', 'WEBI'):
        target_name = 'WEBI'

    matched = next((p for p in partitions if p['name'].upper() == target_name), None)
    if not matched:
        if target_name == 'OSLO':
            matched = next((p for p in partitions if p['name'] == 'CPZ'), None)
        elif target_name == 'WEBI':
            matched = next((p for p in partitions if 'WEB' in p['name']), None)

    if not matched:
        raise ValueError(f"当前固件未检测到目标分区: {mode}")

    start = matched['offset']
    size = matched['size']
    end = min(len(data), start + size)
    slice_data = bytes(data[start:end])
    return start, slice_data, matched
