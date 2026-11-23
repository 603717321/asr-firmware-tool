"""ASR1805 Flash reader/writer. Run with Python, PyQt5 and pyserial."""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time
import struct
import zlib
import xml.etree.ElementTree as ET

from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize, QTimer, QByteArray, QRect, QEvent
from PyQt5.QtGui import QFont, QFontDatabase
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QFormLayout,
    QScrollArea, QGroupBox, QSplitter, QLineEdit, QComboBox, QPushButton,
    QLabel, QTextEdit, QProgressBar, QFileDialog, QMessageBox, QSizePolicy, QMenu,
    QAbstractButton, QAbstractItemView, QTableWidget, QTableWidgetItem, QHeaderView, QGridLayout, QListView, QStyledItemDelegate, QCheckBox,
)

ROOT = Path(__file__).resolve().parent
BACKEND = ROOT / 'asrcode' / 'flash'
RUNS = BACKEND / '读刷工具记录'
if str(BACKEND) not in sys.path:sys.path.insert(0,str(BACKEND))
# Prefer the current package over the archived backend copy.
if str(ROOT) in sys.path:sys.path.remove(str(ROOT))
sys.path.insert(0,str(ROOT))
from asrcode.flash.asr_io_settings import BAUDRATES,baudrate_value,read_state_dir,read_paths,read_metadata_path
from asrcode.flash.asr_manual_at import at_command,send_at
from asrcode.flash.asr_read_recovery import diagnostic_paths
from asrcode.ui.theme import title_font, default_window_rect, bounded_frame
from asrcode.ui.transfer_log import TransferLog, completion_summary
HEIGHT = 34

# Reading and writing share the same purpose labels; retain original TIM IDs.
PARTITION_INFO = {
    'TIMH': ('镜像表 / 启动元数据', '描述镜像项目及其位置、长度等启动元数据。'),
    'OBMI': ('启动镜像', '启动相关镜像。'),
    'OSLO': ('主程序', '主程序镜像，按 TIM 表声明的完整范围读写。'),
    'WEBI': ('网页资源', '设备管理网页资源。'),
    'WIFI': ('WiFi固件', 'WiFi 相关固件镜像。'),
    'RFBN': ('射频配置', '射频相关配置镜像；已检查样本含 RFAPI、FEM 版本标识。是否包含逐机校准数据尚未确认。'),
    'APNL': ('运营商APN', '预置运营商编号、名称、APN 接入点、认证方式及 IP 类型，用于匹配 SIM 卡上网参数。'),
    'RBLI': ('设备/WiFi配置', '配置存储区；已检查样本包含偏好设置、WLANControlConfig.nvm 和定制参数记录。'),
    'GRBI': ('GRBI镜像', '已检查样本包含压缩二进制数据，具体职责尚未确认。'),
    'CPZ': ('主程序', '主程序应用代码（包含AP/PL/CP压缩段，安全刷入不死机）'),
    'WEB': ('网页系统', 'Web前端UI文件系统（解除网页限速与云控页面）'),
}


def partition_display(row):
    name = row['name']
    label = row.get('label') or PARTITION_INFO.get(name, ('用途待确认', '设备原始标识，用途待确认。'))[0]
    description = row.get('desc') or PARTITION_INFO.get(name, ('', '设备原始标识，用途待确认。'))[1]
    risk = row.get('risk', '')
    risk_tag = {'safe': '【推荐/安全】', 'caution': '【注意】', 'danger': '【危险/慎刷】'}.get(risk, '')
    prefix = f"{risk_tag} " if risk_tag else ""
    kib_size = row['size'] // 1024
    text = f"{prefix}{label} {name} · 0x{row['offset']:X} · {kib_size} KiB"
    tooltip = f"{label}（{name}）\n{description}\n偏移：0x{row['offset']:X}，长度：{row['size']:,} 字节 ({kib_size} KiB)\n安全级别：{risk or '普通'}"
    return text, tooltip


class OptionDelegate(QStyledItemDelegate):
    def sizeHint(self, option, index):
        hint = super().sizeHint(option, index)
        hint.setHeight(max(32, option.fontMetrics.height()+12))
        return hint


class VisibleCombo(QComboBox):
    """Use a real list popup rather than the platform's menu-sized combobox popup."""
    def __init__(self):
        super().__init__()
        view = QListView(self)
        view.setUniformItemSizes(True)
        view.setItemDelegate(OptionDelegate(view))
        view.setTextElideMode(Qt.ElideRight)
        view.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        view.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        view.setStyleSheet('QListView { background: white; color: #172333; border: 1px solid #aabbd0; }'
                          'QListView::item { min-height: 28px; padding: 2px 6px; }'
                          'QListView::item:selected { background: #d6e8ff; color: #102c4c; }')
        self.setView(view)
        self.setMaxVisibleItems(10)
        self.setStyleSheet('QComboBox { combobox-popup: 0; }')

    def wheelEvent(self, event):
        if getattr(self, 'ignore_closed_wheel', False) and not self.view().isVisible():
            event.ignore()
            return
        super().wheelEvent(event)

    def showPopup(self):
        view = self.view()
        view.setMinimumHeight(0)
        view.setMaximumHeight(16777215)
        super().showPopup()
        row_height = max(28, view.sizeHintForRow(0))
        height = min(self.maxVisibleItems(), max(1,self.count()))*row_height+4
        screen = QApplication.screenAt(self.mapToGlobal(self.rect().center())) or QApplication.primaryScreen()
        area = screen.availableGeometry()
        height = min(height, max(40, area.height()-40))
        popup = view.window()
        popup.setMinimumHeight(0)
        popup.setMaximumHeight(height)
        popup.resize(max(self.width(), popup.width()), height)
        pos = popup.pos()
        popup.move(max(area.left(), min(pos.x(), area.right()-popup.width()+1)),
                   max(area.top(), min(pos.y(), area.bottom()-height+1)))
        view.scrollTo(view.model().index(max(0,self.currentIndex()),0), QAbstractItemView.EnsureVisible)


class Controls:
    """The only constructor site for all interactive, single-line controls."""
    def __init__(self):
        self.all = []

    def sized(self, control, minimum=96):
        control.setFixedHeight(HEIGHT)
        control.setMinimumWidth(minimum)
        control.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.all.append(control)
        return control

    def combo_editor(self, combo):
        # The combo owns its inner editor geometry; do not force outer height.
        editor = combo.lineEdit()
        editor.setMinimumSize(0,0)
        editor.setMaximumSize(16777215,16777215)
        editor.setSizePolicy(QSizePolicy.Ignored,QSizePolicy.Ignored)
        editor.setStyleSheet('QLineEdit { border: none; border-radius: 0; padding: 0; background: transparent; }')
        self.all.append(editor)
        return editor

    def edit(self, text='', password=False):
        control = self.sized(QLineEdit(text))
        control.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Fixed)
        if password:
            control.setEchoMode(QLineEdit.Password)
        return control

    def combo(self, items=()):
        control = self.sized(VisibleCombo(), 96)
        control.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        control.setMinimumContentsLength(8)
        for text, data in items:
            control.addItem(text, data)
        control.view().setAlternatingRowColors(True)
        return control

    def button(self, text, action):
        control = self.sized(QPushButton(text))
        control.clicked.connect(action)
        return control


def digest_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def decode_soc_info(version_str="", cpuid_str="", cgmm_str=""):
    """Decodes SoC / Master chip from version, CPUID and CGMM."""
    v_upper = str(version_str or "").upper()
    c_upper = str(cgmm_str or "").upper()
    if "FALCONW" in v_upper or "MF808" in v_upper or "MF801" in v_upper:
        soc = "ASR1803 (FalconW Cortex-R5)"
    elif "AQUILA" in v_upper or "3603" in v_upper:
        soc = "ASR3603 (Aquila Cortex-R5)"
    elif "1802" in v_upper:
        soc = "ASR1802 (Cortex-R4/R5)"
    elif "ZX297520" in v_upper or "ZX29" in v_upper:
        soc = "中兴微 ZX297520"
    elif "THREADX" in c_upper:
        soc = "ASR 平台 (ThreadX / Cortex-R5)"
    else:
        soc = "ASR 平台芯片"

    if cpuid_str:
        clean_uid = cpuid_str.strip()
        if clean_uid.lower().startswith("0x"):
            soc += f" [UID: {clean_uid}]"
        elif clean_uid:
            soc += f" [UID: 0x{clean_uid}]"
    return soc


def decode_jedec_id(jedec_bytes):
    """Decodes 3-byte JEDEC ID into Flash manufacturer, model, and capacity."""
    if not jedec_bytes or len(jedec_bytes) < 3:
        return "未知 Flash 芯片"
    if isinstance(jedec_bytes, str):
        try:
            jedec_bytes = bytes.fromhex(jedec_bytes.replace("0x", ""))
        except Exception:
            return "未知 Flash 芯片"

    mfr, mem_type, density = jedec_bytes[0], jedec_bytes[1], jedec_bytes[2]
    if mfr in (0, 0xFF) or density not in range(20, 26):
        return f"未知 JEDEC ID: {bytes(jedec_bytes).hex().upper()}"

    size_mb = 1 << (density - 20)
    mfr_names = {
        0x5E: ("Zbit (恒烁)", "ZB25LQ"),
        0xEF: ("Winbond (华邦)", "W25Q"),
        0xC8: ("GigaDevice (兆易创新)", "GD25Q"),
        0x85: ("Puya (普冉)", "P25Q"),
        0x0B: ("XTX (芯天下)", "XT25F"),
        0xC2: ("Macronix (旺宏)", "MX25L"),
        0x68: ("Boya (博雅)", "BY25Q"),
        0x1C: ("EON (宜扬)", "EN25Q"),
        0x20: ("Micron (美光)", "N25Q"),
    }

    mfr_names[0x20] = ("XTX (芯天下) / Micron", "XT25F / N25Q")
    mfr_info = mfr_names.get(mfr, (f"厂商0x{mfr:02X}", "SPI-NOR-"))
    if mfr == 0x20 and mem_type in (0x40, 0x41):
        chip_name = f"XT25F{size_mb*8} (XTX 芯天下 / Micron)"
    else:
        chip_name = f"{mfr_info[1]}{size_mb*8} ({mfr_info[0]})"
    return f"{chip_name} · {size_mb} MiB QSPI NOR [0x{bytes(jedec_bytes).hex().upper()}]"


def compute_luhn_checksum(digits14: str) -> int:
    """Computes the 15th Luhn check digit for a 14-digit IMEI prefix."""
    digits = [int(c) for c in str(digits14) if c.isdigit()][:14]
    total = 0
    for i, d in enumerate(digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return (10 - (total % 10)) % 10


def autocomplete_imei(prefix: str, default_template: str = '000000000000000') -> str:
    from asrcode.imei.randomizer import random_imei
    value=str(prefix).strip()
    from asrcode.imei.writer import complete_imei
    return random_imei(value) if len(value)<14 else complete_imei(value)


def decode_firmware_hardware_targets(data, size):
    """Inspects firmware binary for target SoC and Flash specifications."""
    data_sample = data[:min(len(data), 0x200000)]
    soc = "ASR1803 (FalconW Cortex-R5)" if (b"FALCONW" in data or b"MF808" in data or b"MF801" in data) else "ASR 平台芯片"
    size_kib = size // 1024
    size_mib = size / 1048576
    flash = f"{size_kib} KiB ({size_mib:.2f} MiB) QSPI NOR Flash (ZB25LQ64 / W25Q64 兼容系列)"
    return soc, flash


def inspect_image(path):
    path = Path(path).resolve()
    if path.suffix.lower() != '.bin':
        raise ValueError('固件刷入仅支持BIN镜像文件')
    size = path.stat().st_size
    metadata = read_metadata_path(path)
    if metadata.exists():
        try:
            state = json.loads(metadata.read_text(encoding='utf-8'))
        except (ValueError,OSError):
            state = {}
        if state.get('complete') is False:
            raise ValueError('该读取文件未通过完整校验，不能作为刷入镜像；请新建文件重新读取')
    with path.open('rb') as stream:
        header = stream.read(8)
    with path.open('rb') as stream:
        data = stream.read()
    if header[4:8] == b'HMIT':
        from asrcode.flash.asr_tim_integrity import require_valid
        require_valid(data)
    if str(BACKEND) not in sys.path:
        sys.path.insert(0, str(BACKEND))
    from asrcode.flash.asr_device_model import extract_firmware_version_and_model
    version, model = extract_firmware_version_and_model(data, path.name)
    imeis = set(m.decode('ascii') for m in re.findall(
        rb'(?i)(?:<imei>\s*|\bimei[\x00\s:=\"\']{1,16})([0-9]{15})(?![0-9])', data))
    # IMEI.bin is an MRD record; accept it only in an Adler-verified filesystem.
    from asrcode.firmware.fwdecon.hmit import Firmware, FECACE, HEAD, HDR, NAME
    start = data.find(FECACE)
    while start >= 0:
        end = Firmware._chain_end(data, start + HEAD)
        if end and zlib.adler32(data[start+8:end]) & 0xffffffff == struct.unpack_from('<I', data, start+4)[0]:
            entry = start + HEAD
            while entry + HDR + NAME <= end and data[entry+2:entry+4] == b'\xfe\xca':
                length = struct.unpack_from('<I', data, entry+4)[0] & 0xffffff
                payload = entry + HDR + NAME
                if payload + length > end:
                    break
                if data[entry+HDR:payload].split(b'\0', 1)[0] == b'IMEI.bin':
                    imeis.update(x.decode('ascii') for x in re.findall(rb'(?<![0-9])[0-9]{15}(?![0-9])', data[payload:payload+length]))
                entry = payload + length
        start = data.find(FECACE, start+4)
    partitions = []
    partition_error = ''
    if size in (0x100000,0x200000,0x400000,0x800000,0x1000000) and header[4:8] == b'HMIT':
        try:
            from asrcode.firmware.partitions import discover_universal_partitions
            partitions = discover_universal_partitions(data)
        except Exception:
            if str(BACKEND) not in sys.path:
                sys.path.insert(0, str(BACKEND))
            from asrcode.flash.qspi_flash_writer import firmware_partitions
            try:
                partitions = firmware_partitions(data)
            except ValueError as exc:
                partition_error = str(exc)
    soc, flash_chip = decode_firmware_hardware_targets(data, size)
    return {'path': str(path), 'size': size, 'version': version or '固件未识别', 'model': model or '', 'sha256': digest_file(path),
            'partitions': partitions, 'partition_error': partition_error,
            'imei': next(iter(imeis)) if len(imeis) == 1 else '',
            'full_image': size in (0x100000,0x200000,0x400000,0x800000,0x1000000) and header[4:8] == b'HMIT',
            'soc': soc, 'flash_chip': flash_chip}


class Worker(QThread):
    line = pyqtSignal(str)
    result = pyqtSignal(object)

    def __init__(self, kind, params, parent=None):
        super().__init__(parent)
        if kind not in ('probe', 'inspect', 'read', 'write', 'at', 'power', 'write_imei'):
            raise ValueError('Unknown operation kind: ' + str(kind))
        self.kind = kind
        self.params = dict(params)
        self.baudrate = baudrate_value(self.params.get("baudrate",115200))
        self.cancel = threading.Event()
        anchor = self.params.get('path') or self.params.get('output')
        record_parent = Path(anchor).resolve().parent if anchor else Path(self.params.get('record_dir') or ROOT).resolve()
        self.run_dir = record_parent / '读刷工具记录' / str(time.time_ns())
        self.stop_file = self.run_dir / 'stop.request'

    def stop(self):
        self.cancel.set()
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.stop_file.touch()

    def emit_line(self, text):
        self.line.emit(text)
        if hasattr(self, '_log'):
            self._log.write(text + '\n')
            self._log.flush()

    def run(self):
        outcome = {'kind': self.kind, 'success': False, 'cancelled': False}
        try:
            self.run_dir.mkdir(parents=True, exist_ok=True)
            with (self.run_dir / 'operation.log').open('w', encoding='utf-8') as log:
                self._log = log
                if self.kind == 'probe':
                    outcome.update(self.probe())
                elif self.kind == 'at':
                    outcome.update(self.manual_at())
                elif self.kind == 'power':
                    outcome.update(self.power_action())
                elif self.kind == 'write_imei':
                    outcome.update(self.write_imei_action())
                elif self.kind == 'inspect':
                    outcome.update(success=True, image=inspect_image(self.params['path']))
                elif self.kind in ('read', 'write'):
                    outcome.update(self.transfer())
                else:
                    raise ValueError('Unknown operation kind: ' + str(self.kind))
        except Exception as exc:
            outcome['error'] = str(exc)
            self.line.emit('失败：' + str(exc))
        finally:
            outcome['cancelled'] = outcome.get('cancelled', False) or self.cancel.is_set()
            if outcome['cancelled']:
                outcome['success'] = False
            outcome['run_dir'] = str(self.run_dir)
            (self.run_dir / 'result.json').write_text(
                json.dumps(outcome, ensure_ascii=False, indent=2), encoding='utf-8')
            self.result.emit(outcome)


    def power_action(self):
        action = self.params['action']
        mode = self.params.get('mode', 'at')
        labels = {'reboot': '重启', 'poweroff': '关机', 'restore_defaults': '恢复出厂'}
        label = labels.get(action, action)

        if mode == 'at':
            import serial
            from asrcode.flash.operation_control import check_stop
            port_name = self.params['port']
            baud = self.params.get('baudrate', self.baudrate)
            self.emit_line(f'【AT模式】正在通过串口 {port_name} 发送{label}指令...')

            with serial.Serial(port_name, baud, timeout=.001, write_timeout=3) as wire:
                wire.reset_input_buffer()
                if action == 'reboot':
                    cmd = 'AT+CFUN=1,1'
                    self.emit_line(f'AT发送：{cmd}')
                    res = send_at(wire, cmd, check_cancel=lambda: check_stop(self.stop_file))
                    reply = res.get('reply', b'').decode('utf-8', errors='replace').strip()
                    self.emit_line(f'AT应答：{reply or "OK"}')
                elif action == 'poweroff':
                    cmd = 'AT+CFUN=0'
                    self.emit_line(f'AT发送：{cmd}')
                    res = send_at(wire, cmd, check_cancel=lambda: check_stop(self.stop_file))
                    reply = res.get('reply', b'').decode('utf-8', errors='replace').strip()
                    self.emit_line(f'AT应答：{reply or "OK"}')
                elif action == 'restore_defaults':
                    self.emit_line('AT发送：AT*MRDRESTORE（恢复出厂）')
                    try:
                        res1 = send_at(wire, 'AT*MRDRESTORE', check_cancel=lambda: check_stop(self.stop_file))
                        self.emit_line(f'AT应答：{res1.get("reply", b"").decode("utf-8", errors="replace").strip()}')
                    except Exception as e:
                        self.emit_line(f'跳过：{e}')
                    self.emit_line('AT发送：AT&F')
                    try:
                        res2 = send_at(wire, 'AT&F', check_cancel=lambda: check_stop(self.stop_file))
                        self.emit_line(f'AT应答：{res2.get("reply", b"").decode("utf-8", errors="replace").strip()}')
                    except Exception as e:
                        self.emit_line(f'跳过：{e}')
                    self.emit_line('AT发送：AT+CFUN=1,1（重启生效）')
                    res3 = send_at(wire, 'AT+CFUN=1,1', check_cancel=lambda: check_stop(self.stop_file))
                    reply3 = res3.get('reply', b'').decode('utf-8', errors='replace').strip()
                    self.emit_line(f'AT应答：{reply3 or "OK"}')
            self.emit_line(f'【AT模式】{label}指令下发完成')
            return {'success': True, 'action': action, 'mode': 'at', 'command_accepted': True}
        else:
            from asrcode.flash.asr_probe import normalize_ip
            endpoints = {'reboot': 'reset', 'poweroff': 'power_off', 'restore_defaults': 'restore_defaults'}
            if action not in endpoints:raise ValueError('未知电源操作')
            ip = normalize_ip(self.params['ip'])
            if not ip:raise ValueError('请输入设备IP地址')
            import asrcode.http.client as module
            client = module.AsrHttp(ip,self.params['user'],self.params['password'],log=self.emit_line)
            if not client.login():raise RuntimeError('后台登录失败，未发送电源指令')
            if self.cancel.is_set():return {'success':False,'cancelled':True}
            self.emit_line('【URL模式】发送'+label+'指令：'+ip+'，file='+endpoints[action])
            status, body = client.get(endpoints[action],allow_destructive=True)
            self.emit_line('设备应答：HTTP '+str(status)+'；'+str(body)[:300])
            accepted = 200 <= status < 300
            if not accepted:
                raise RuntimeError(label+'指令未获成功应答；设备可能已执行，请先检查设备状态，避免重复发送')
            return {'success':True,'action':action,'mode':'url','ip':ip,'http_status':status,
                    'response':str(body)[:2000],'command_accepted':True,'state_verified':False}

    def write_imei_action(self):
        import serial
        from asrcode.flash.operation_control import check_stop
        from asrcode.imei.reader import query_imei
        from asrcode.imei.writer import replace_imei
        self.run_dir.mkdir(parents=True,exist_ok=True)
        def save(report):
            path=self.run_dir/'IMEI修改记录.json'
            temp=path.with_suffix('.tmp')
            with temp.open('w',encoding='utf-8') as stream:
                json.dump(report,stream,ensure_ascii=False,indent=2)
                stream.flush();os.fsync(stream.fileno())
            temp.replace(path)
        self.emit_line('开始修改IMEI：先读取原值并保存，写后分别核对MRD与运行时IMEI。')
        with serial.Serial(self.params['port'],self.baudrate,timeout=.001,write_timeout=3) as wire:
            wire.reset_input_buffer()
            result=replace_imei(wire,self.params['imei'],send_at,query_imei,
                                check_cancel=lambda:check_stop(self.stop_file),log=lambda text: None,save=save)
        if result.get('success'):
            self.emit_line('IMEI与目标一致，无需修改。' if result.get('unchanged') else 'IMEI修改完成：MRD与运行时回读均一致；尚未验证重启。')
        else:
            self.emit_line('IMEI修改未完成：'+result.get('error','请查看修改记录'))
            if result.get('rollback_verified'):self.emit_line('原IMEI已恢复并通过MRD回读核对。')
        return result

    def manual_at(self):
        import serial
        from asrcode.flash.operation_control import check_stop
        command=at_command(self.params['command'])
        self.emit_line('AT发送：'+command+'；串口 '+self.params['port']+'；波特率 '+str(self.baudrate))
        with serial.Serial(self.params['port'],self.baudrate,timeout=.001,write_timeout=3) as wire:
            wire.reset_input_buffer()
            if self.params.get('read_imei'):
                from asrcode.imei.reader import query_imei
                result=query_imei(wire,send_at,check_cancel=lambda:check_stop(self.stop_file),log=self.emit_line)
                result['host_baudrate']=self.baudrate
                folder=self.run_dir/'过程文件';folder.mkdir(parents=True,exist_ok=True)
                (folder/'AT原始响应.bin').write_bytes(result['reply'].encode('utf-8'))
                return result
            result=send_at(wire,command,check_cancel=lambda:check_stop(self.stop_file))
        folder=self.run_dir/'过程文件';folder.mkdir(parents=True,exist_ok=True)
        (folder/'AT原始响应.bin').write_bytes(result['reply'])
        reply=result.pop('reply').decode('utf-8',errors='replace')
        self.emit_line('AT应答：\n'+(reply.strip() or '（无应答）'))
        result.update(command=command,reply=reply,host_baudrate=self.baudrate)
        if not result['success']:
            result['error']='等待AT结束应答超时，指令可能已经执行' if result.get('timed_out') else ('AT响应超出捕获上限' if result.get('limit_reached') else '设备返回AT错误应答')
        return result

    def probe(self):
        from serial.tools import list_ports
        if str(BACKEND) not in sys.path:
            sys.path.insert(0, str(BACKEND))
        import asrcode.flash.at_flash_backup as api
        ports = list(list_ports.comports())
        # Probe only ASR candidates or the port explicitly selected by the user.
        candidates = [p for p in ports if p.vid in (0x2ecc, 0x1286) or 'ASR' in p.description.upper()
                      or p.device == self.params.get('port')]
        candidates.sort(key=lambda p: (p.device != self.params.get('port'), p.device))
        rows = [{'port': p.device, 'description': p.description} for p in ports]
        selected = None
        errors = []
        for candidate in (candidates if self.params.get('scope') != 'web' else []):
            if self.cancel.is_set():
                break
            self.emit_line('探测 AT：' + candidate.device)
            try:
                with api.serial.Serial(candidate.device, self.baudrate, timeout=.001, write_timeout=3) as port:
                    api.synchronize(port)
                    selected = {'port': candidate.device, 'baudrate':self.baudrate, 'version': '', 'imei': '',
                                'partitions': [], 'header': '', 'read_supported': False,
                                'write_supported': False, 'capability_error': ''}
                    for command, field in [('AT+CGMR\r', 'version'), ('AT+CGSN\r', 'imei'), ('AT+CGMM\r', 'cgmm'), ('AT*READCPUUID\r', 'cpuid')]:
                        try:
                            reply = api.exchange(port, command).decode(errors='replace').strip()
                            if field == 'imei':
                                match = re.search(r'(?<!\d)(\d{15})(?!\d)', reply)
                                selected[field] = match[1] if match else ''
                            elif field == 'cgmm':
                                match = re.search(r'\+CGMM:\s*"?([^"\r\n]+)"?', reply)
                                selected[field] = match[1].strip() if match else ''
                            elif field == 'cpuid':
                                match = re.search(r'\*READCPUUID:\s*(0x[0-9a-fA-F]+|[0-9a-fA-F]+)', reply)
                                selected[field] = match[1].strip() if match else ''
                            elif 'ERROR' not in reply:
                                from asrcode.flash.asr_probe import at_version_text
                                selected[field] = at_version_text(reply)
                        except Exception as exc:
                            self.emit_line('可选信息查询跳过：'+str(exc))
                    selected['soc'] = decode_soc_info(selected.get('version'), selected.get('cpuid'), selected.get('cgmm'))
                    from asrcode.flash.asr_device_model import resolve_device_model
                    selected['model'] = resolve_device_model(serial_info=selected, image_info=getattr(self, 'image', None))
                    # Reading is detected from the device protocol and TIM, independently
                    # of the device-specific QSPI programming profile.
                    try:
                        api.synchronize(port)
                        selected.update(api.detect_flash_read_profile(port, self.stop_file))
                    except Exception as exc:
                        selected['read_error'] = str(exc)
                        self.emit_line('Flash 读取探测未通过：'+str(exc))
                    try:
                        from asrcode.flash.qspi_profile import discover_profile
                        try:
                            selected['write_profile'] = discover_profile(lambda address, count: api.read_words(port, address, count))
                        except ValueError as exc:
                            if 'Unsupported QSPI NOR command capability' in str(exc):
                                try:
                                    BASE = 0xd420b000
                                    lock = struct.unpack('<I', api.read_words(port, BASE + 0x304, 1))[0]
                                    api.exchange(port, f'AT*REGRW=w,{BASE+0x300:08x},5af05af0\r')
                                    api.exchange(port, f'AT*REGRW=w,{BASE+0x304:08x},00000002\r')
                                    api.exchange(port, f'AT*REGRW=w,{BASE+0x3f0:08x},00000406\r')
                                    api.exchange(port, f'AT*REGRW=w,{BASE+0x3f4:08x},00000000\r')
                                    api.exchange(port, f'AT*REGRW=w,{BASE+0x3f8:08x},00000000\r')
                                    api.exchange(port, f'AT*REGRW=w,{BASE+0x3fc:08x},00000000\r')
                                    for i in range(4):
                                        api.exchange(port, f'AT*REGRW=w,{BASE+0x400+i*4:08x},00000000\r')
                                    api.exchange(port, f'AT*REGRW=w,{BASE+0x300:08x},5af05af0\r')
                                    api.exchange(port, f'AT*REGRW=w,{BASE+0x304:08x},{lock:08x}\r')
                                    self.emit_line('QSPI LUT Slot 1 (WREN) 已自动修复')
                                    selected['write_profile'] = discover_profile(lambda address, count: api.read_words(port, address, count))
                                except Exception:
                                    raise exc
                            else:
                                raise
                        selected['write_supported'] = 0 < selected.get('flash_size', 0) <= 0x1000000
                    except Exception as exc:
                        selected['capability_error'] = '写入未匹配：' + str(exc)

                    # Directly query physical JEDEC ID via QSPI slot 15
                    try:
                        BASE = 0xd420b000
                        saved = [struct.unpack('<I', api.read_words(port, BASE + 0x400 + i*4, 1))[0] for i in range(4)]
                        lock = struct.unpack('<I', api.read_words(port, BASE + 0x304, 1))[0]
                        api.exchange(port, f'AT*REGRW=w,{BASE+0x300:08x},5af05af0\r')
                        api.exchange(port, f'AT*REGRW=w,{BASE+0x304:08x},00000002\r')
                        for i, val in enumerate((0x1c00049f, 0, 0, 0)):
                            api.exchange(port, f'AT*REGRW=w,{BASE+0x400+i*4:08x},{val:08x}\r')
                        r0 = struct.unpack('<I', api.read_words(port, BASE, 1))[0]
                        api.exchange(port, f'AT*REGRW=w,{BASE:08x},{r0|0x400:08x}\r')
                        api.exchange(port, f'AT*REGRW=w,{BASE+0x16c:08x},00000100\r')
                        api.exchange(port, f'AT*REGRW=w,{BASE+0x100:08x},80000000\r')
                        api.exchange(port, f'AT*REGRW=w,{BASE+0x110:08x},00000100\r')
                        r160 = struct.unpack('<I', api.read_words(port, BASE+0x160, 1))[0]
                        api.exchange(port, f'AT*REGRW=w,{BASE+0x160:08x},{r160:08x}\r')
                        api.exchange(port, f'AT*REGRW=w,{BASE+8:08x},{(15<<24)|3:08x}\r')
                        import time; time.sleep(0.01)
                        jedec_raw = api.read_words(port, 0xd420b200, 1)[:3]
                        api.exchange(port, f'AT*REGRW=w,{BASE+0x300:08x},5af05af0\r')
                        api.exchange(port, f'AT*REGRW=w,{BASE+0x304:08x},00000002\r')
                        for i, val in enumerate(saved):
                            api.exchange(port, f'AT*REGRW=w,{BASE+0x400+i*4:08x},{val:08x}\r')
                        api.exchange(port, f'AT*REGRW=w,{BASE+0x304:08x},{lock:08x}\r')
                        if jedec_raw and jedec_raw[0] not in (0, 0xFF):
                            selected['jedec_id'] = jedec_raw.hex().upper()
                            selected['flash_chip'] = decode_jedec_id(jedec_raw)
                    except Exception:
                        pass
                    if not selected.get('flash_chip') and selected.get('flash_size'):
                        f_sz = selected['flash_size']
                        selected['flash_chip'] = f"{f_sz // 1024} KiB ({f_sz / 1048576:.2f} MiB) QSPI NOR Flash"
                    self.emit_line('AT 响应正常：' + candidate.device)
                    break
            except Exception as exc:
                errors.append(candidate.device + ': ' + str(exc))
                self.emit_line(errors[-1])
        web = {'success': False}
        web_devices = []
        if not self.cancel.is_set() and self.params.get('scope') != 'serial':
            from asrcode.flash.asr_probe import discover_gateways, has_asr_web, query_device_info
            from asrcode.flash.asr_ip_discovery import iter_ip_candidates,should_finish_web
            candidates_ip = iter_ip_candidates(self.params.get('ip'),discover_gateways,self.emit_line,self.cancel.is_set)
            import asrcode.http.client as module
            for candidate_ip in candidates_ip:
                if self.cancel.is_set():
                    break
                ip = candidate_ip['ip']
                self.emit_line('检测后台：'+ip+'（'+candidate_ip.get('interface', '')+'）')
                try:
                    if not has_asr_web(ip):
                        self.emit_line(ip+'：未识别到 ASR 管理页面')
                        continue
                    client = module.AsrHttp(ip, self.params['user'], self.params['password'], log=self.emit_line)
                    login = client.login()
                    values,info_source,attempts = query_device_info(client) if login else ({},'',[])
                    from asrcode.flash.asr_device_model import resolve_device_model
                    web_model = values.get('hardware_version') or values.get('model_name') or resolve_device_model(values=values, web_ip=ip, serial_info=selected, image_info=getattr(self, 'image', None)) or '未返回型号'
                    item = {'success': bool(login and values), 'ip': ip,
                            'model': web_model,
                            'version': values.get('version_num', ''), 'status': 200 if values else (attempts[-1]['status'] if attempts else 0),
                            'info_source':info_source,'attempts':attempts,
                            'imei': values.get('IMEI') or values.get('imei') or '未返回',
                            'device_type': values.get('device_type') or values.get('model_name') or values.get('device_name') or ('ASR / 新版 XML' if 'home_data' in info_source else '未返回')}
                    if item['success']:
                        web_devices.append(item)
                        if should_finish_web(item,(selected or {}).get('imei','')):
                            self.emit_line('已找到可用ASR后台：'+ip+'；停止后续IP探测')
                            break
                        self.emit_line('后台IMEI未匹配当前AT设备，继续查找匹配设备')
                    else:
                        errors.append(ip+'：后台登录或状态查询未通过')
                except Exception as exc:
                    errors.append(ip+': '+str(exc))
                    self.emit_line('后台探测：'+errors[-1])
            if web_devices:
                web = next((item for item in web_devices if selected and selected.get('imei') and item.get('imei')==selected['imei']),web_devices[0])
            else:
                web['error'] = '未发现可登录的 ASR 后台；可手动输入地址重试'
        return {'success': bool(selected) or web.get('success', False), 'scope': self.params.get('scope', 'all'),
                'ports': rows, 'serial': selected, 'web': web, 'web_devices': web_devices, 'errors': errors}

    def transfer(self):
        params = self.params
        if self.kind == 'read':
            output = Path(params['output']).resolve()
            if params['fresh'] and output.exists():
                if not params.get('overwrite'):
                    raise ValueError('同名文件已出现，请重新点击读取并确认是否覆盖。')
                if self.cancel.is_set():
                    return {'cancelled': True, 'exit_code': 2}
            args = ['-m', 'asrcode.flash.at_flash_backup', '--port', params['port'], '--baudrate',str(self.baudrate),
                    '--output', str(output), '--base', params.get('base', '0x80000000'), '--length', params.get('length', '0x800000'),
                    '--stop-file', str(self.stop_file)]
            args.extend(['--state-dir',str(read_state_dir(output)), '--records-dir',str(self.run_dir/'过程文件')])
            if params.get('partition'):
                args.extend(['--partition', params['partition']])
            self.emit_line('读取范围：'+str(params.get('partition') or '整机')+
                           '，地址 '+params.get('base', '0x80000000')+
                           '，长度 '+params.get('length', '0x800000'))
            args.append('--reread-verify' if params.get('reread_verify',True) else '--no-reread-verify')
            if params['fresh']:
                args.append('--fresh')
                if params.get('overwrite'):
                    args.append('--overwrite')
        else:
            image = inspect_image(params['path'])
            if image != params['image']:
                raise ValueError('镜像文件发生变化，请重新检查后刷入')
            if params['mode'] == 'full' and not image['full_image']:
                raise ValueError('整机模式需要完整 HMIT 镜像')
            if params.get('backup_firmware', True) and not params.get('resume_write'):
                backup_dir = self.run_dir.parent / '刷入前备份'
                backup_dir.mkdir(parents=True, exist_ok=True)
                ts = time.strftime('%Y%m%d_%H%M%S')
                mode_tag = params.get('mode', 'full')
                backup_file = (backup_dir / f"Flash_backup_{mode_tag}_{ts}.bin").resolve()
                self.emit_line(f"【刷前防护】开始自动备份当前设备固件至：{backup_file.name}")
                bkp_args = [sys.executable, '-X', 'utf8', '-m', 'asrcode.flash.at_flash_backup',
                            '--port', params['port'], '--baudrate', str(self.baudrate),
                            '--output', str(backup_file), '--base', '0x80000000',
                            '--length', hex(params.get('flash_size') or 0x800000),
                            '--stop-file', str(self.stop_file), '--fresh', '--overwrite',
                            '--records-dir', str(self.run_dir/'过程文件')]
                bkp_args.append('--reread-verify' if params.get('reread_verify', True) else '--no-reread-verify')
                with subprocess.Popen(bkp_args, cwd=str(ROOT),
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                        encoding='utf-8', errors='replace', bufsize=1,
                        env={**os.environ, 'PYTHONUTF8': '1', 'PYTHONIOENCODING': 'utf-8', 'PYTHONUNBUFFERED': '1'},
                        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)) as bkp_proc:
                    for b_raw in bkp_proc.stdout:
                        b_line = b_raw.rstrip()
                        if b_line:
                            self.emit_line('  [备份] ' + b_line)
                    bkp_proc.wait()
                    if bkp_proc.returncode != 0 or not backup_file.exists():
                        raise RuntimeError(f"刷入前固件备份未成功 (退出码 {bkp_proc.returncode})，为保护设备已中止刷入！")
                    self.emit_line("【刷前防护】固件备份完成，安全进入刷入流程。")
            args = ['-m', 'asrcode.flash.direct_flash', '--port', params['port'], '--baudrate',str(self.baudrate), '--input', image['path'],
                    '--mode', params['mode'], '--offset', params['offset'],
                    '--stop-file', str(self.stop_file)]
            for name in ('verify', 'erase', 'skip_equal'):
                args.append(('--' if (name=='erase' or params.get(name, True)) else '--no-') + name.replace('_', '-'))
            args.extend(['--records-root',str(self.run_dir.parent),'--run-dir',str(self.run_dir/'过程文件')])
            args.append('--resume-check' if params.get('resume_check',True) else '--no-resume-check')
            if params.get('resume_write'):
                args.append('--resume-write')
        if self.cancel.is_set():
            return {'cancelled': True, 'exit_code': 2}
        self.emit_line('任务记录：' + str(self.run_dir))
        self.emit_line('串口：' + params['port']+'，波特率：'+str(self.baudrate))
        result_path = None
        backend_tail=[]
        with subprocess.Popen([sys.executable, '-X', 'utf8', *args], cwd=str(ROOT),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                encoding='utf-8', errors='replace', bufsize=1,
                env={**os.environ, 'PYTHONUTF8': '1', 'PYTHONIOENCODING': 'utf-8', 'PYTHONUNBUFFERED': '1'},
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)) as process:
            for raw in process.stdout:
                line = raw.rstrip()
                if line:
                    backend_tail.append(line);backend_tail=backend_tail[-30:]
                if line.startswith('READ_MISMATCH '):
                    self.read_decision = None
                    self.read_decision_event = threading.Event()
                    self.emit_line(line)
                    while not self.read_decision_event.wait(.1):
                        if self.cancel.is_set():
                            break
                    process.stdin.write(('continue' if self.read_decision == 'continue' and not self.cancel.is_set() else 'stop')+'\n')
                    process.stdin.flush()
                else:
                    self.emit_line(line)
                if line.startswith('RESULT '):
                    result_path = Path(line[7:])
            code = process.wait()
        details = {}
        if self.kind == 'read':
            result_path = read_metadata_path(output)
        if result_path and result_path.exists():
            details = json.loads(result_path.read_text(encoding='utf-8'))
        verified = details.get('complete' if self.kind == 'read' else 'success', False)
        error=details.get('error','')
        if not verified and not error:
            error=('后端退出码 '+str(code)+'；'+backend_tail[-1]) if backend_tail else '后端没有返回有效结果；退出码 '+str(code)
        return {'success': code == 0 and verified,
                'cancelled': code == 2 and (self.cancel.is_set() or bool(details.get('cancelled'))),
                'error':error,'exit_code': code, 'details': details, 'backend_result': str(result_path or '')}


class Window(QMainWindow):
    def __init__(self, config_path=None):
        super().__init__()
        configure_font(QApplication.instance())
        self.setWindowTitle('ASR固件读刷工具V1.0')
        self.config_path = Path(config_path) if config_path else ROOT/'ASR固件读刷工具.config.json'
        self.factory = Controls()
        self.worker = None
        self.last_result = None
        self.profile = None
        self.image = None
        self.groups = []
        self.busy_controls = []
        self.setting_probe = False
        self.build()
        screen = QApplication.primaryScreen().availableGeometry()
        self.setGeometry(default_window_rect(screen))
        self.port.currentIndexChanged.connect(self.invalidate_serial)
        self.baudrate.currentTextChanged.connect(self.invalidate_serial)
        self.ip.currentTextChanged.connect(self.invalidate_web)
        self.ip.lineEdit().textEdited.connect(self.invalidate_web)
        self.user.textEdited.connect(self.invalidate_web)
        self.password.textEdited.connect(self.invalidate_web)
        self.image_path.textChanged.connect(self.invalidate_image)
        self.mode.currentIndexChanged.connect(self.update_mode)
        self.read_range.currentIndexChanged.connect(
            self.update_read_range)
        for screen_handle in QApplication.screens():
            screen_handle.availableGeometryChanged.connect(lambda _: self.screen_adjust())
        self.update_mode()
        self.refresh_enabled()
        self.load_config()

    def label(self, text):
        label = QLabel(text)
        label.setWordWrap(True)
        label.setMinimumWidth(0)
        label.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        return label

    def group(self, title):
        group = QGroupBox(title)
        group.setMinimumWidth(0)
        group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        box = QVBoxLayout(group)
        box.setContentsMargins(10, 14, 10, 8)
        box.setSpacing(6)
        self.left_layout.addWidget(group)
        self.groups.append(group)
        return box

    def row(self, layout, *widgets):
        row = QHBoxLayout()
        for widget in widgets:
            row.addWidget(widget, 0 if isinstance(widget, QPushButton) else 1)
        layout.addLayout(row)

    def status(self, target, text, state):
        color = {'ok': '#16803c', 'bad': '#c63b35', 'busy': '#a96a00', 'idle': '#687787'}[state]
        target.setText('●  ' + text)
        target.setProperty('state', state)
        target.setStyleSheet('color: '+color+'; font-weight: 600;')

    def table(self, rows):
        table = QTableWidget(0, 3)
        table.setHorizontalHeaderLabels(['序号', '信息项', '参数'])
        table.setAlternatingRowColors(True)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.verticalHeader().hide()
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Fixed)
        table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Fixed)
        table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        table.setColumnWidth(0, 48)
        table.setColumnWidth(1, 112)
        table.setMinimumWidth(0)
        table.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Fixed)
        row_height = max(24, self.fontMetrics().height()+6)
        table.verticalHeader().setDefaultSectionSize(row_height)
        table.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        table.horizontalHeader().setFixedHeight(row_height)
        table.setFixedHeight(row_height*6+2*table.frameWidth())
        self.fill_table(table, rows)
        table.setContextMenuPolicy(Qt.CustomContextMenu)
        table.customContextMenuRequested.connect(lambda point, view=table: self.table_copy_menu(view, point))
        return table

    def table_copy_menu(self, table, point):
        item = table.itemAt(point)
        if item is None:
            return
        row = item.row()
        menu = QMenu(self)
        value = menu.addAction('复制参数值')
        parameter = menu.addAction('复制参数名和值')
        all_parameters = menu.addAction('复制全部参数')
        chosen = menu.exec_(table.viewport().mapToGlobal(point))
        if chosen == value:
            text = table.item(row, 2).text()
        elif chosen == parameter:
            text = table.item(row, 1).text()+'\t'+table.item(row, 2).text()
        elif chosen == all_parameters:
            text = '\n'.join(table.item(r, 1).text()+'\t'+table.item(r, 2).text() for r in range(table.rowCount()))
        else:
            return
        QApplication.clipboard().setText(text)

    def fill_table(self, table, rows):
        table.setRowCount(len(rows))
        for index, (name, value) in enumerate(rows):
            for column, text in enumerate((str(index+1), name, str(value))):
                item = QTableWidgetItem(text)
                item.setToolTip(text)
                if column == 0:
                    item.setTextAlignment(Qt.AlignCenter)
                table.setItem(index, column, item)

    def build(self):
        c = self.factory
        self.splitter = QSplitter(Qt.Horizontal)
        self.splitter.splitterMoved.connect(lambda *_: self.layout_log_toolbar())
        self.setCentralWidget(self.splitter)
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setMinimumWidth(320)
        content = QWidget()
        self.left_layout = QVBoxLayout(content)
        self.left_layout.setContentsMargins(10, 10, 10, 10)
        self.left_layout.setSpacing(8)
        self.scroll.setWidget(content)
        self.splitter.addWidget(self.scroll)
        self.right = QWidget()
        self.right.setMinimumWidth(210)
        self.right.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Expanding)
        right_layout = QVBoxLayout(self.right)
        right_layout.setContentsMargins(8, 10, 10, 10)
        self.log_toolbar = QGridLayout()
        self.log_toolbar.setSpacing(6)
        right_layout.addLayout(self.log_toolbar)
        self.clear_log = c.button('清空', lambda: self.log.clear())
        self.wrap_log = c.button('自动换行', self.toggle_wrap)
        self.wrap_log.setCheckable(True)
        self.wrap_log.setChecked(True)
        self.time_log = c.button('时间戳', lambda: None)
        self.time_log.setCheckable(True)
        self.copy_log = c.button('复制日志', self.copy_log_text)
        self.support_button = c.button('鼓励作者', self.show_support)
        self.save_config_button = c.button('保存配置', self.save_config)
        self.toolbar_buttons = [self.clear_log, self.wrap_log, self.time_log, self.copy_log, self.support_button, self.save_config_button]
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.document().setMaximumBlockCount(3000)
        self.log.setMinimumWidth(0)
        right_layout.addWidget(self.log, 1)
        self.splitter.addWidget(self.right)
        self.splitter.setStretchFactor(0, 7)
        self.splitter.setStretchFactor(1, 3)
        self.splitter.setSizes([770, 330])
        self.splitter.splitterMoved.connect(lambda *_: self.layout_log_toolbar())

        box = self.group('① 设备连接')
        grid = QGridLayout()
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(8)
        grid.addWidget(QLabel('AT 串口'), 0, 0)
        self.port = c.combo([('请检测端口', None)])
        serial_row=QHBoxLayout()
        serial_row.setSpacing(8)
        serial_row.addWidget(self.port,3)
        grid.addLayout(serial_row,0,1,1,2)
        self.port_probe_button = c.button('端口检测', lambda: self.probe('serial'))
        grid.addWidget(self.port_probe_button, 0, 3)
        serial_row.addWidget(QLabel('波特率'))
        self.baudrate = c.combo([(str(rate),rate) for rate in BAUDRATES])
        self.baudrate.setEditable(True)
        self.baudrate.setCurrentIndex(self.baudrate.findData(115200))
        self.baudrate.setToolTip('电脑端AT串口连接速率；USB虚拟串口推荐921600以获得最优速率（物理串口默认115200）')
        c.combo_editor(self.baudrate)
        serial_row.addWidget(self.baudrate,2)
        grid.addWidget(QLabel('IP 地址'), 1, 0)
        self.ip = c.combo()
        self.ip.setEditable(True)
        self.ip.lineEdit().setPlaceholderText('自动发现本机网关，或输入设备 IP')
        c.combo_editor(self.ip)
        grid.addWidget(self.ip, 1, 1, 1, 2)
        self.ip_probe_button = c.button('IP 检测', lambda: self.probe('web'))
        grid.addWidget(self.ip_probe_button, 1, 3)
        grid.addWidget(QLabel('账号 / 密码'), 2, 0)
        self.user = c.edit('admin')
        self.password = c.edit('admin')
        self.user.setPlaceholderText('后台账号')
        self.password.setPlaceholderText('后台密码')
        credentials_widget = QWidget()
        credentials = QHBoxLayout(credentials_widget)
        credentials.setContentsMargins(0,0,0,0)
        credentials.setSpacing(8)
        self.user.setSizePolicy(QSizePolicy.Preferred,QSizePolicy.Fixed)
        self.password.setSizePolicy(QSizePolicy.Preferred,QSizePolicy.Fixed)
        self.user.setMaximumWidth(160)
        self.password.setMaximumWidth(160)
        credentials.addWidget(self.user)
        credentials.addWidget(self.password)
        self.reboot_button = c.button('重启',lambda:self.device_power('reboot'))
        self.poweroff_button = c.button('关机',lambda:self.device_power('poweroff'))
        self.restore_button = c.button('恢复出厂',lambda:self.device_power('restore_defaults'))
        self.restore_button.setToolTip('恢复出厂设置（清除动态NVRAM中残留的云端限速和拦截，重载出厂预置配置）')
        credentials.addWidget(self.reboot_button)
        credentials.addWidget(self.poweroff_button)
        credentials.addWidget(self.restore_button)
        self.power_mode = c.combo([('AT模式', 'at'), ('URL模式', 'url')])
        self.power_mode.setToolTip('选择 重启/关机/恢复出厂 的触发方式（AT模式走串口，URL模式走管理后台）')
        self.power_mode.setMaximumWidth(110)
        credentials.addWidget(self.power_mode)
        for control in (self.user,self.password,self.reboot_button,self.poweroff_button,self.restore_button,self.power_mode):
            control.setMinimumWidth(60)
        credentials.addStretch(1)
        grid.addWidget(credentials_widget,2,1,1,3)
        for column in (1, 2, 3):
            grid.setColumnStretch(column, 1)

        # Quick AT commands row
        grid.addWidget(QLabel('快捷AT'), 3, 0)
        quick_at_widget = QWidget()
        quick_at_layout = QHBoxLayout(quick_at_widget)
        quick_at_layout.setContentsMargins(0, 0, 0, 0)
        quick_at_layout.setSpacing(6)
        self.quick_at_buttons = []
        for cmd in ['ATI', 'AT+FLASHBP=0', 'AT*PROD=1', 'AT*PROD=0', 'AT*PROD?', 'AT*LTEBAND?']:
            btn = c.button(cmd, lambda checked=False, command=cmd: self.quick_send_at(command))
            btn.setFixedHeight(28)
            btn.setToolTip(f'点击快速发送：{cmd}')
            quick_at_layout.addWidget(btn)
            self.quick_at_buttons.append(btn)
        quick_at_layout.addStretch(1)
        grid.addWidget(quick_at_widget, 3, 1, 1, 3)

        # AT input row
        grid.addWidget(QLabel('AT指令'), 4, 0)
        self.at_input = c.edit('AT')
        self.at_input.setPlaceholderText('输入AT指令，回车或点击发送')
        self.at_input.returnPressed.connect(self.send_at_command)
        self.at_send_button = c.button('发送', self.send_at_command)
        grid.addWidget(self.at_input, 4, 1, 1, 2)
        grid.addWidget(self.at_send_button, 4, 3)

        # IMEI modification row
        grid.addWidget(QLabel('IMEI修改'), 5, 0)
        imei_widget = QWidget()
        imei_layout = QHBoxLayout(imei_widget)
        imei_layout.setContentsMargins(0, 0, 0, 0)
        imei_layout.setSpacing(8)
        self.imei_autocomplete = QCheckBox('自动补全')
        self.imei_autocomplete.setChecked(True)
        self.imei_autocomplete.setToolTip('1至13位保留前缀随机补全；14位计算校验码；15位原样使用并检查校验码。输入框不变。')
        self.imei_input = c.edit('')
        self.imei_input.setPlaceholderText('输入15位IMEI或前n位')
        self.imei_input.setToolTip('待写入的IMEI；勾选自动补全时可只输入前n位（默认000000000000000）')
        self.write_imei_button = c.button('写入IMEI', self.write_imei)
        self.read_imei_button = c.button('读取IMEI', self.read_imei)
        self.read_imei_button.setToolTip('查询设备当前IMEI，读取成功后回填输入框，不修改设备。')
        self.write_imei_button.setToolTip('通过AT指令将IMEI写入设备NVRAM')
        imei_layout.addWidget(self.imei_autocomplete)
        imei_layout.addWidget(self.imei_input, 1)
        imei_layout.addWidget(self.read_imei_button)
        imei_layout.addWidget(self.write_imei_button)
        grid.addWidget(imei_widget, 5, 1, 1, 3)
        box.addLayout(grid)
        self.serial_light = self.label('')
        self.web_light = self.label('')
        self.serial_light.hide()
        self.web_light.hide()
        self.status(self.serial_light, '串口未验证', 'idle')
        self.status(self.web_light, '后台未验证', 'idle')
        actions = QHBoxLayout()
        self.probe_button = c.button('获取设备信息', self.probe)
        self.stop_button = c.button('停止当前操作', self.stop)
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setMinimumWidth(80)
        actions.addWidget(self.probe_button)
        actions.addWidget(self.stop_button)
        actions.addWidget(self.progress, 1)
        box.addLayout(actions)
        self.task_light = self.label('')
        self.status(self.task_light, '就绪', 'idle')
        self.task_light.hide()
        self.device_values = {}
        self.device_table = self.table([('设备型号', '待探测'), ('主芯片', '待探测'), ('Flash 芯片', '待探测'),
                                       ('固件版本', '待探测'), ('IMEI', '待探测'), ('Flash 容量', '待验证'),
                                       ('设备形态', '待探测'), ('可写状态', '待验证')])
        box.addWidget(self.device_table)
        self.device_info = self.label('')
        self.device_info.hide()

        box = self.group('② 固件读取')
        self.output = c.edit(str(ROOT / ('Flash_'+time.strftime('%Y%m%d_%H%M%S')+'.bin')))
        self.pick_output_button = c.button('选择保存位置', self.pick_output)
        self.row(box, self.output, self.pick_output_button)
        self.read_action = c.combo([('新建文件', 'new'), ('续读', 'resume')])
        self.read_range = c.combo([('整机（长度待探测）', 'full')])
        self.read_range.ignore_closed_wheel = True
        self.read_range.setToolTip('探测 AT 端口后，按设备实际 TIM 表生成分区读取范围')
        self.row(box, self.read_action, self.read_range)
        self.read_reread_verify = c.sized(QCheckBox('复读校验'))
        self.read_reread_verify.setChecked(True)
        self.read_reread_verify.setToolTip('默认开启双重比对校验（每次读取2遍严格比对），确保固件零误码、绝无比特翻转风险。')
        self.read_button = c.button('读取固件', self.read_flash)
        read_footer = QHBoxLayout()
        read_footer.addWidget(self.read_reread_verify)
        read_footer.addStretch(1)
        read_footer.addWidget(self.read_button)
        box.addLayout(read_footer)

        box = self.group('③ 固件刷入')
        self.image_path = c.edit()
        self.image_path.setPlaceholderText('选择需要刷入的 BIN 镜像')
        self.pick_image_button = c.button('选择固件', self.pick_image)
        self.row(box, self.image_path, self.pick_image_button)
        self.mode = c.combo([('整机固件', 'full'), ('主程序 OSLO', 'oslo'), ('局部数据', 'patch')])
        self.mode.ignore_closed_wheel = True
        self.offset = c.edit('0x0')
        self.offset.setPlaceholderText('Flash 偏移')
        self.check_image_button = c.button('核对固件信息', self.inspect)
        self.row(box, self.mode, self.offset, self.check_image_button)
        self.image_light = self.label('')
        self.status(self.image_light, '未选择镜像', 'idle')
        self.write_button = c.button('刷入固件', self.write_flash)
        self.resume_write_button = c.button('续写固件', lambda: self.write_flash(True))
        self.image_light.hide()
        self.write_backup = c.sized(QCheckBox('备份固件'))
        self.write_backup.setChecked(True)
        self.write_backup.setToolTip('刷入前自动读取当前设备固件并备份至“读刷工具记录/刷入前备份”目录，确保可随时回退救援。')
        self.write_verify = c.sized(QCheckBox('写后校验'))
        self.write_skip_equal = c.sized(QCheckBox('跳过同块'))
        for control in (self.write_backup, self.write_verify, self.write_skip_equal):
            control.setChecked(True)
        self.write_verify.setToolTip('勾选后每次写入后立即回读比较；不勾选可提升写入速度，但在边界保护时仍会读取验证。')
        self.write_skip_equal.setToolTip('先扫描选定范围，若与当前固件相同则跳过写入；可大幅保护Flash寿命并加速。')
        self.resume_check = c.sized(QCheckBox('续写核对'))
        self.resume_check.setChecked(True)
        self.resume_check.setToolTip('勾选后续写前先核对已有块；取消则仅根据记录直接从断点继续。')
        self.write_options_layout=QGridLayout()
        box.addLayout(self.write_options_layout)
        self.layout_write_options(False)
        self.scroll.viewport().installEventFilter(self)
        self.row(box, self.resume_write_button, self.write_button)
        self.firmware_table = self.table([('固件型号', '待核对'), ('主芯片', '待核对'), ('Flash 芯片', '待核对'),
                                         ('固件大小', '未选择'), ('固件架构', '待核对'), ('固件版本', '待核对'),
                                         ('SHA-256', '待核对'), ('IMEI', '待核对')])
        box.addWidget(self.firmware_table)
        self.image_info = self.label('')
        self.image_info.hide()
        self.task_info = self.label('待写块固定先擦除再写入；相同块按勾选项跳过，停止会完成当前4 KiB块。')
        self.task_info.setTextInteractionFlags(Qt.TextSelectableByMouse)
        box.addWidget(self.task_info)
        self.left_layout.addStretch(1)
        self.busy_controls = [self.read_imei_button,self.reboot_button,self.poweroff_button,self.restore_button,self.power_mode,self.at_input,self.at_send_button,self.port, self.baudrate, self.ip, self.user, self.password, self.probe_button,*self.quick_at_buttons,self.imei_autocomplete,self.imei_input,self.write_imei_button,
            self.port_probe_button, self.ip_probe_button, self.image_path, self.pick_image_button,
            self.check_image_button, self.output, self.pick_output_button, self.read_action,
            self.read_range, self.read_reread_verify, self.write_backup, self.resume_check, self.mode, self.offset, self.write_verify, self.write_skip_equal]
        for view in self.findChildren(QAbstractItemView):
            view.setAlternatingRowColors(True)
        self.setStyleSheet('''
            QMainWindow, QScrollArea { background: #f3f5f8; }
            QScrollArea { border: none; }
            QSplitter::handle { background: #e0e6ee; width: 6px; }
            QGroupBox { background: white; border: 1px solid #d8e0e9; border-radius: 8px;
                        margin-top: 10px; font-weight: 600; }
            QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 5px; }
            QLineEdit, QComboBox { background: white; border: 1px solid #b7c5d6;
                                 border-radius: 4px; padding: 3px 6px; font-size: 13px; }
            QLineEdit:focus, QComboBox:focus { border: 1px solid #4c8bd4; }
            QTextEdit { background: white; border: 1px solid #b7c5d6; border-radius: 3px; padding: 4px; }
            QPushButton { border: 1px solid #b7c5d6; border-radius: 5px; background: #edf3fa; padding: 0 6px; }
            QPushButton:hover { background: #dbeafa; }
            QPushButton:disabled { color: #8794a3; background: #eef1f5; }
            QPushButton:checked { background: #dbeafe; border-color: #7aa9dd; color: #194f86; }
            QAbstractItemView { alternate-background-color: #edf3fa; background-color: white; }
            QTableWidget { border: 1px solid #c9d4e0; gridline-color: #d9e1eb; }
            QHeaderView::section { background: #e8eef5; padding: 4px; border: 0;
                                   border-right: 1px solid #d1dbe6; }
            QProgressBar { border: 1px solid #bac9d9; border-radius: 4px; text-align: center; }
            QProgressBar::chunk { background: #88aed6; }
            QToolTip { background: #ffffff; color: #25354a; border: 1px solid #c9d4e0; padding: 5px; }
        ''')
        self.layout_log_toolbar()

    def layout_log_toolbar(self):
        columns = max(1, min(5, (self.right.width()-18)//102))
        while self.log_toolbar.count():
            self.log_toolbar.takeAt(0)
        for index, button in enumerate(self.toolbar_buttons):
            self.log_toolbar.addWidget(button, index//columns, index%columns)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self, 'toolbar_buttons'):
            self.layout_log_toolbar()
        if hasattr(self,'write_options_layout'):
            self.layout_write_options()

    def toggle_wrap(self):
        self.log.setLineWrapMode(QTextEdit.WidgetWidth if self.wrap_log.isChecked() else QTextEdit.NoWrap)

    def copy_log_text(self):
        selected = self.log.textCursor().selectedText()
        QApplication.clipboard().setText(selected.replace('\u2029', '\n') if selected else self.log.toPlainText())

    def append_log(self, text):
        if self.time_log.isChecked():
            text = '['+time.strftime('%H:%M:%S')+'] '+text
        self.log.append(text)

    def invalidate_serial(self, *_):
        if self.setting_probe:
            return
        self.profile = None
        self.refresh_read_partitions()
        self.status(self.serial_light, '串口已更改，请重新探测', 'idle')
        self.refresh_enabled()

    def invalidate_web(self, *_):
        if not self.setting_probe:
            self.status(self.web_light, '连接参数已更改，后台未验证', 'idle')

    def invalidate_image(self, *_):
        self.image = None
        self.refresh_partition_modes()
        self.fill_table(self.firmware_table, [('固件型号', '待核对'), ('主芯片', '待核对'), ('Flash 芯片', '待核对'), ('固件大小', '未选择'), ('固件架构', '待核对'), ('固件版本', '待核对'), ('SHA-256', '待核对'), ('IMEI', '待核对')])
        self.status(self.image_light, '镜像待检查', 'idle')
        self.refresh_enabled()

    def update_read_range(self, *_):
        self.preferred_read_range = self.read_range.currentData()
        self.refresh_enabled()

    def refresh_read_partitions(self):
        selected = getattr(self, 'preferred_read_range', self.read_range.currentData())
        self.read_range.blockSignals(True)
        self.read_range.clear()
        size = (self.profile or {}).get('flash_size', 0)
        self.read_range.addItem(f'整机（{size//1024} KiB / {size/1048576:g} MiB）' if size else '整机（长度待探测）', 'full')
        for row in (self.profile or {}).get('partitions', []):
            name = row['name']
            mode = 'oslo' if name == 'OSLO' else 'tim:'+name
            text, tooltip = partition_display(row)
            self.read_range.addItem(text, mode)
            self.read_range.setItemData(self.read_range.count()-1, tooltip, Qt.ToolTipRole)
        index = self.read_range.findData(selected)
        self.read_range.setCurrentIndex(index if index >= 0 else 0)
        self.read_range.blockSignals(False)
        self.refresh_enabled()

    def refresh_partition_modes(self):
        selected = self.mode.currentData()
        self.mode.blockSignals(True)
        self.mode.clear()
        img_size = (self.image or {}).get('size', 0)
        self.mode.addItem(f'整机固件 (full · {img_size//1024} KiB)' if img_size else '整机固件 (full)', 'full')
        partitions = (self.image or {}).get('partitions', [])
        if not partitions:
            self.mode.addItem('主程序 OSLO', 'oslo')
        for row in partitions:
            name = row['name']
            mode = 'oslo' if name in ('OSLO', 'CPZ') else ('web' if name in ('WEB', 'WEBI') else 'tim:'+name)
            text, tooltip = partition_display(row)
            self.mode.addItem(text, mode)
            self.mode.setItemData(self.mode.count()-1, tooltip, Qt.ToolTipRole)
        self.mode.addItem('局部补丁（指定偏移）', 'patch')
        index = self.mode.findData(selected)
        if index < 0:
            index = self.mode.findData('oslo')
            if index < 0:
                index = self.mode.findData('web')
        self.mode.setCurrentIndex(index if index >= 0 else 0)
        self.mode.blockSignals(False)
        self.update_mode()

    def update_mode(self, *_):
        mode = self.mode.currentData()
        self.offset.setEnabled(mode == 'patch' and self.worker is None)
        if mode != 'patch':
            row = next((r for r in (self.image or {}).get('partitions', [])
                        if mode == ('oslo' if r['name'] in ('OSLO', 'CPZ') else ('web' if r['name'] in ('WEB', 'WEBI') else 'tim:'+r['name']))), None)
            self.offset.setText(hex(row['offset']) if row else ('0x0' if mode == 'full' else '0x20000'))
        self.refresh_enabled()



    def layout_write_options(self,wide=None):
        if wide is None:wide=self.scroll.viewport().width()>=740
        grid=self.write_options_layout
        while grid.count():grid.takeAt(0)
        for column in range(5):grid.setColumnStretch(column,0)
        controls = (self.write_backup, self.write_verify, self.write_skip_equal, self.resume_check)
        if wide:
            for col, ctrl in enumerate(controls):
                grid.addWidget(ctrl, 0, col)
                grid.setColumnStretch(col, 1)
        else:
            for idx, ctrl in enumerate(controls):
                grid.addWidget(ctrl, idx // 2, idx % 2)
                grid.setColumnStretch(idx % 2, 1)

    def eventFilter(self,watched,event):
        if hasattr(self,'write_options_layout') and watched is self.scroll.viewport() and event.type()==QEvent.Resize:
            self.layout_write_options(event.size().width()>=740)
        return super().eventFilter(watched,event)

    def refresh_enabled(self):
        busy = self.worker is not None
        for widget in self.busy_controls:
            widget.setEnabled(not busy)
        self.offset.setEnabled(not busy and self.mode.currentData() == 'patch')
        self.stop_button.setEnabled(busy and not self.worker.cancel.is_set() if busy else False)
        readable = bool(self.profile and self.profile.get('read_supported'))
        writable = bool(self.profile and self.profile.get('write_supported'))
        readable_range = self.read_range.currentData() != 'full' or bool((self.profile or {}).get('flash_size'))
        self.read_button.setEnabled(not busy and readable and readable_range)
        valid = self.image and (self.mode.currentData() != 'full' or self.image['full_image'])
        self.write_button.setEnabled(not busy and writable and bool(valid))
        self.resume_write_button.setEnabled(not busy and writable and bool(valid))

    def start(self, kind, params):
        if kind not in ('probe', 'inspect', 'read', 'write', 'at', 'power', 'write_imei'):
            QMessageBox.warning(self, '操作不支持', '未知操作类型');return
        if self.worker is not None:
            return
        if kind in ('at','read','write','write_imei') or (kind=='power' and params.get('mode')=='at') or (kind=='probe' and params.get('scope')!='web'):
            try:params={**params,'baudrate':baudrate_value(self.baudrate.currentText())}
            except ValueError as exc:
                QMessageBox.warning(self,'波特率无效',str(exc));return
        self._progress_log_state={}
        self._transfer_log=TransferLog()
        self.progress.setValue(0)
        self.resumed_from = 0
        self.write_resumed_from = 0
        self.started = time.monotonic()
        self.pending_result = None
        self.last_result = None
        self.worker = Worker(kind, params, self)
        self.worker.line.connect(self.on_line)
        self.worker.result.connect(self.on_result)
        self.worker.finished.connect(self.on_finished)
        self.status(self.task_light, {'probe': '探测设备', 'inspect': '检查镜像',
                    'read': '读取', 'write': '刷入','at':'发送AT指令','power':'设备电源操作','write_imei':'写入IMEI'}[kind], 'busy')
        self.append_log('\n===== '+self.task_light.text()+' =====')
        self.refresh_enabled()
        self.worker.start()
        if kind in ('read', 'write'):
            self.scroll.ensureWidgetVisible(self.groups[0])

    def device_power(self, action):
        if self.worker is not None:return
        if action not in ('reboot','poweroff','restore_defaults'):return
        labels={'reboot':'重启','poweroff':'关机','restore_defaults':'恢复出厂'}
        label=labels.get(action, action)
        mode = self.power_mode.currentData() or 'at'
        anchor = self.image_path.text().strip() or self.output.text()

        if mode == 'at':
            port = self.port.currentData()
            if not port:
                QMessageBox.warning(self, '选择AT串口', '【AT模式】请先检测并选择AT串口');return
            message = f'确定通过AT串口 {port} 对设备执行【{label}】操作吗？'
            if action == 'poweroff':
                message += '\n关机后可能需要按设备电源键重新开机。'
            elif action == 'restore_defaults':
                message += '\n将通过AT指令清除设备动态NVRAM中残留的限速与拦截，恢复出厂配置并重启。'
            if QMessageBox.question(self, f'确认{label}（AT模式）', message, QMessageBox.Yes|QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
                return
            self.start('power', {'action': action, 'mode': 'at', 'port': port,
                                'record_dir': str(Path(anchor or str(ROOT/'固件')).resolve().parent)})
        else:
            from asrcode.flash.asr_probe import normalize_ip
            try:
                ip=normalize_ip(self.ip.currentText())
                if not ip:raise ValueError('请输入设备IP地址')
            except ValueError as exc:
                QMessageBox.warning(self,'IP地址无效',str(exc));return
            message='确定通过Web后台（'+ip+'）对设备执行【'+label+'】操作吗？'
            if action=='poweroff':message+='\n关机后可能需要按设备电源键重新开机。'
            elif action=='restore_defaults':message+='\n将清除设备动态NVRAM中残留的云端限速与认证拦截，恢复去控预置配置并自动重启。'
            if QMessageBox.question(self,'确认'+label+'（URL模式）',message,QMessageBox.Yes|QMessageBox.No,QMessageBox.No)!=QMessageBox.Yes:return
            self.start('power',{'action':action, 'mode': 'url', 'ip':ip,'user':self.user.text(),'password':self.password.text(),
                                'record_dir':str(Path(anchor or str(ROOT/'固件')).resolve().parent)})

    def quick_send_at(self, command):
        self.at_input.setText(command)
        self.send_at_command()

    def send_at_command(self):
        if self.worker is not None:return
        port=self.port.currentData()
        if not port:
            QMessageBox.warning(self,'选择AT串口','请先检测并选择AT串口');return
        try:command=at_command(self.at_input.text())
        except ValueError as exc:
            QMessageBox.warning(self,'AT指令无效',str(exc));return
        anchor=self.image_path.text().strip() or self.output.text()
        self.start('at',{'port':port,'command':command,'record_dir':str(Path(anchor).resolve().parent)})

    def read_imei(self):
        if self.worker is not None:return
        port=self.port.currentData()
        if not port:
            QMessageBox.warning(self,'选择AT串口','请先检测并选择AT串口');return
        anchor=self.image_path.text().strip() or self.output.text()
        self.start('at',{'port':port,'command':'AT+CGSN','read_imei':True,
                         'record_dir':str(Path(anchor).resolve().parent)})

    def write_imei(self):
        if self.worker is not None:
            return
        port = self.port.currentData()
        if not port:
            QMessageBox.warning(self, '选择AT串口', '请先检测并选择AT串口')
            return
        raw_imei = self.imei_input.text().strip()
        if not raw_imei:
            QMessageBox.warning(self, 'IMEI无效', '请输入IMEI或前缀')
            return
        if self.imei_autocomplete.isChecked():
            try:
                final_imei = autocomplete_imei(raw_imei)
            except Exception as e:
                QMessageBox.warning(self, 'IMEI格式错误', str(e))
                return
            self.append_log(f'【IMEI自动补全】完整IMEI：{final_imei}')
        else:
            final_imei = raw_imei
            if not re.fullmatch(r'[0-9]{15}',final_imei):
                QMessageBox.warning(self, 'IMEI格式错误', 'IMEI必须为15位数字（或勾选自动补全）')
                return
        from asrcode.imei.writer import complete_imei
        try:complete_imei(final_imei)
        except ValueError as exc:
            QMessageBox.warning(self,'IMEI校验位错误',str(exc));return
        if QMessageBox.question(self, '确认修改IMEI',
                                f'确定要将设备 IMEI 写入为：\n{final_imei}\n\n先保存原IMEI，必要时重建MRD记录；写后回读核对。',
                                QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            return
        anchor = self.image_path.text().strip() or self.output.text()
        self.start('write_imei', {
            'port': port,
            'imei': final_imei,
            'record_dir': str(Path(anchor or str(ROOT / '固件')).resolve().parent)
        })

    def probe(self, scope='all'):
        if not isinstance(scope, str):
            scope = 'all'
        if scope != 'web':
            self.profile = None
            self.refresh_read_partitions()
            self.status(self.serial_light, '正在验证 AT 串口', 'busy')
        if scope != 'serial':
            self.status(self.web_light, '正在验证后台登录', 'busy')
        self.start('probe', {'port': self.port.currentData(), 'ip': self.ip.currentText().strip(),
                            'user': self.user.text(), 'password': self.password.text(), 'scope': scope,
                            'record_dir': str(Path(self.image_path.text().strip() or self.output.text()).resolve().parent)})

    def pick_image(self):
        path, _ = QFileDialog.getOpenFileName(self, '选择固件镜像', str(ROOT), 'BIN 镜像 (*.bin)')
        if path:
            self.image_path.setText(path)
            self.inspect()

    def inspect(self):
        if not self.image_path.text().strip():
            QMessageBox.warning(self, '选择镜像', '请选择或输入BIN固件镜像路径。')
            return
        self.status(self.image_light, '正在检查镜像', 'busy')
        self.start('inspect', {'path': self.image_path.text().strip()})

    def pick_output(self):
        path, _ = QFileDialog.getSaveFileName(self, '保存固件或分区数据', self.output.text(), 'BIN 镜像 (*.bin)')
        if path:
            self.output.setText(path)

    def read_flash(self):
        if not self.profile or not self.profile.get('read_supported'):
            return
        if not self.output.text().strip():
            QMessageBox.warning(self, '保存路径', '请选择输出文件。')
            return
        fresh = self.read_action.currentData() == 'new'
        overwrite = fresh and Path(self.output.text().strip()).exists()
        if overwrite:
            if QMessageBox.question(self, '确认覆盖',
                    '文件已存在，是否覆盖并从头读取？\n'+self.output.text().strip(),
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
                return
        mode = self.read_range.currentData()
        if mode == 'full' and not self.profile.get('flash_size'):
            QMessageBox.warning(self, '整机长度未确认', '请重新探测端口，或选择已识别的分区读取。')
            return
        row = None
        if mode != 'full':
            name = 'OSLO' if mode == 'oslo' else str(mode)[4:]
            row = next((r for r in self.profile.get('partitions', []) if r['name'] == name), None)
            if row is None:
                QMessageBox.warning(self, '分区未识别', '请重新探测设备分区表后选择读取范围。')
                return
        self.start('read', {'port': self.profile['port'], 'output': self.output.text().strip(),
                           'fresh': fresh, 'overwrite': overwrite,
                           'base': hex(self.profile.get('flash_base', 0x80000000)+(row['offset'] if row else 0)),
                           'length': hex(row['size'] if row else self.profile['flash_size']),
                           'partition': row['name'] if row else None, 'reread_verify': self.read_reread_verify.isChecked()})

    def write_flash(self, resume_write=False):
        if self.worker:
            return
        if not self.image or not self.profile or not self.profile.get('write_supported'):
            return
        mode = self.mode.currentData()
        device_imei = getattr(self, 'device_values', {}).get('IMEI')
        if mode == 'full' and self.image.get('imei') and device_imei and self.image['imei'] != device_imei:
            self.append_log('镜像与设备 IMEI 不同；按所选整机模式刷入，身份与校准数据也会覆盖。')
        try:
            offset = int(self.offset.text().strip(), 0)
            if offset < 0 or (mode == 'patch' and offset+self.image['size'] > self.profile.get('flash_size',0)):
                raise ValueError('局部数据超出已探测 Flash 范围')
            if mode == 'full' and self.image['size'] != self.profile.get('flash_size'):
                raise ValueError('整机镜像长度与已探测 Flash 容量不同')
            if mode == 'full' and not self.image['full_image']:
                raise ValueError('整机刷入需要完整 HMIT 镜像')
            if str(BACKEND) not in sys.path:
                sys.path.insert(0, str(BACKEND))
            from asrcode.flash.qspi_flash_writer import prepare_input
            target_offset, target_data = prepare_input(self.image['path'], mode, offset)
            if mode == 'oslo' or mode.startswith('tim:'):
                offset = target_offset
                self.offset.setText(hex(offset))
        except ValueError as exc:
            QMessageBox.warning(self, '参数错误', str(exc))
            return
        options = {name: control.isChecked() for name, control in self.config_write_options().items()}
        options['erase']=True
        text = ('串口：'+self.profile['port']+'\n镜像：'+self.image['path']+
                '\n模式：'+self.mode.currentText()+f'\n实际范围：0x{target_offset:X}，{len(target_data):,} 字节'+
                '\n'+ ' / '.join(label+('：开' if options[name] else '：关') for name, label in
                                  [('verify','校验'),('erase','擦除'),('skip_equal','跳过相同')])+
                ('\n续写核对：'+('开' if self.resume_check.isChecked() else '关，已完成前缀不回读') if resume_write else '')+
                '\n停止会完成当前 4 KiB 块；不创建备份。继续？')
        if QMessageBox.question(self, '确认刷入', text, QMessageBox.Yes | QMessageBox.No,
                                QMessageBox.No) != QMessageBox.Yes:
            return
        self.start('write', {'port': self.profile['port'], 'path': self.image['path'],
                            'image': dict(self.image), 'mode': mode, 'offset': hex(offset), 'resume_write':bool(resume_write),
                            'resume_check':self.resume_check.isChecked(), 'flash_size': (self.profile or {}).get('flash_size'),
                            'backup_firmware': self.write_backup.isChecked(), **options})

    def stop(self):
        if self.worker:
            self.worker.stop()
            self.status(self.task_light, '停止请求已发送，等待当前事务结束', 'busy')
            self.stop_button.setEnabled(False)

    def on_line(self, line):
        if not hasattr(self, '_transfer_log'):
            self._transfer_log = TransferLog()
        resumed=getattr(self,'resumed_from',0) if line.startswith('READ ') else getattr(self,'write_resumed_from',0)
        event=self._transfer_log.progress(line,resumed)
        if event is not None:
            if 'status' in event:
                self.progress.setValue(event['percent'])
                self.task_info.setText(event['status'])
                if event.get('log'):self.append_log(event['log'])
            return
        if line.startswith(('SECTOR_BEGIN ','SECTOR ','PROGRESS write ','COMPLETE ')):
            return
        if line.startswith('CANCELLED '):
            self.append_log('【已停止】'+('读取断点已保留，可选择“续读”继续。' if 'read;' in line else '写入已停止，已完成块记录可用于续写。'))
            return
        if line.startswith(('READ_RETRY ','AHB_RETRY ')):
            address=re.search(r'0x[0-9a-fA-F]+',line)
            attempt=re.search(r'attempt=(\d+)/(\d+)',line)
            self.append_log('【自动重读】'+(address[0] if address else '')+
                            (f' · 第 {attempt[1]}/{attempt[2]} 次' if attempt else '')+' · 当前结果已丢弃，重新读取核对。')
            return
        if line.startswith('WRITE_READ_TRANSPORT '):
            self.append_log('写入任务读取通道：'+line[len('WRITE_READ_TRANSPORT '):])
            return
        if line.startswith('READ_TRANSPORT '):
            info=json.loads(line[len('READ_TRANSPORT '):])
            self.append_log('读取通道：'+info['transport']+
                            ('；会话内关闭回显' if info['echo_disabled'] else ''))
            if info.get('probe_error'):self.append_log('加速预检未通过，使用原读取通道：'+info['probe_error'])
            return
        if line.startswith('WRITE_PLAN '):
            eq = re.search(r'equal=(\d+)', line)
            diff = re.search(r'different=(\d+)', line)
            eq_cnt = int(eq[1]) if eq else 0
            diff_cnt = int(diff[1]) if diff else 0
            self.append_log(f"全范围差异扫描完成：相同块={eq_cnt} ({(eq_cnt*4096)/1048576:.2f} MiB)，待写入不同块={diff_cnt} ({(diff_cnt*4096)/1048576:.2f} MiB)")
            self.task_info.setText(f"扫描完成：待写入 {diff_cnt} 个差异块")
            return
        if line.startswith('READ_RECOVERY '):
            info=json.loads(line[len('READ_RECOVERY '):])
            labels={'discard_frame':'响应受干扰，整次响应已丢弃，自动重读',
                    'recovered':'通信已恢复，继续读取',
                    'smaller_frames':'复读不一致，自动缩小帧重读',
                    'mapped_fallback':'自动降级普通AT读取，本次会话保持保守模式'}
            message=labels.get(info['action'],info['action'])+f"；地址 0x{info['address']:X}"
            if 'attempt' in info:message+=f"；第{info['attempt']}次"
            self.append_log(message);self.task_info.setText(message)
            return
        if line.startswith('READ_DISAGREEMENT '):
            info=json.loads(line[len('READ_DISAGREEMENT '):])
            location=info.get('first_difference_address',info['address'])
            self.append_log(f"读取数据不一致：第 {info['attempts']} 组，块地址 0x{info['address']:X}，"
                            f"差异 {info['differing_bytes']} 字节，首处 0x{location:X}；当前组已丢弃。")
            return
        if line.startswith('WRITE_RESUME '):
            self.write_resumed_from = int(line.split()[1])
            self.append_log(f'续写跳过已完成前缀：{self.write_resumed_from:,} 字节（未复核）')
            return
        if line.startswith('READ_MISMATCH '):
            info = json.loads(line[len('READ_MISMATCH '):])
            worker = self.worker
            if worker is None:
                return
            box = QMessageBox(self)
            box.setWindowTitle('复读校验不一致')
            box.setText(f"地址 0x{info['address']:X}，{info['length']} 字节：自动恢复和复读后仍不一致（{info.get('attempts',2)}组）。")
            if 'first_difference_address' in info:
                box.setDetailedText(f"本组差异：{info['differing_bytes']} 字节\n"
                                    f"首处差异地址：0x{info['first_difference_address']:X}\n"
                                    f"两个样本 SHA-256：\n"+'\n'.join(info.get('hashes',[]))+
                                    '\n差异窗口（十六进制）：\n'+'\n'.join(info.get('difference_sample',[])))
            box.setInformativeText('继续将保留该块最后一次读数并标记异常，保持后续地址不变；该文件不能作为已校验镜像刷入。')
            stop = box.addButton('停止读取', QMessageBox.RejectRole)
            proceed = box.addButton('继续读取下一块', QMessageBox.AcceptRole)
            box.setDefaultButton(stop)
            box.exec_()
            worker.read_decision = 'continue' if box.clickedButton() == proceed else 'stop'
            worker.read_decision_event.set()
            return
        display=line
        translations={'READ_RETRY':'读取重试','AHB_RETRY':'映射读取重试','RESUME_CHECK':'续读检查',
                      'RESUME_VERIFY':'续读边界核对','RESUME_WRITE':'续写记录','RESUME':'读取断点',
                      'SECTOR_BEGIN':'开始写入扇区','SECTOR':'扇区','PROGRESS':'进度',
                      'COMPLETE':'操作完成','RESULT':'结果记录','INPUT':'输入范围','CANCELLED':'操作已停止',
                      'READ':'读取','WRITE_SPEED':'写入速度'}
        for key in sorted(translations,key=len,reverse=True):
            if line.startswith(key+' '):
                display=translations[key]+line[len(key):];break
        for source,target in [('verified','校验通过'),('elapsed=','耗时='),('attempt=','次数='),
                              ('block not committed','当前块未提交'),('command complete; no readback','命令完成，未回读'),
                              ('write ','写入 '),('verify ','校验 '),('preflight ','写前检查 '),('compare ','全范围差异扫描 ')]:
            display=display.replace(source,target)
        if line.startswith('COMPLETE '):display='操作完成，详细参数与校验结果已保存到结果记录。'
        for source,target in [('mode=full','范围=整机'),('mode=oslo','范围=主程序'),('mode=patch','范围=局部'),
                              ('offset=','偏移='),('length=','长度='),('rechecking device contents before skipping','跳过前重新核对设备'),
                              ('discarded IP1/IP2/mapped set','丢弃当前交叉读取结果'),
                              ('reread with conservative batches','使用较小批次重新读取'),
                              ('current sector completed; readback','当前块已完成；回读'),
                              ('read;','读取；'),('write;','写入；'),
                              ('enabled','已启用'),('not requested','未启用'),
                              ('verified partial file preserved','已保留断点文件')]:
            display=display.replace(source,target)
        if line.startswith('Traceback '):
            folder=getattr(self.worker,'run_dir',None)
            display='后台发生错误；原始日志：'+str(Path(folder)/'operation.log' if folder else '请查看本任务记录目录中的operation.log')
        elif line.startswith('  File ') or re.match(r'^\s+(?:[~^]+|[A-Za-z_].*)',line):
            return
        if re.match(r'^(?:RuntimeError|ValueError|TimeoutError|SerialException|OSError|OperationCancelled):',line):
            display=self.friendly_error(line)+'\n原始错误：'+line
        self.append_log(display)
        resumed = re.search(r'RESUME (0x[0-9a-fA-F]+)', line)
        if resumed:
            self.resumed_from = int(resumed[1], 16)
        verify = re.search(r'RESUME_VERIFY (0x[0-9a-fA-F]+)/(0x[0-9a-fA-F]+)',line)
        if verify:
            done,total=int(verify[1],16),int(verify[2],16)
            self.progress.setValue(0)
            self.task_info.setText(f'核对已有文件：{done/1048576:.2f} / {total/1048576:.2f} MiB')

    @staticmethod
    def friendly_error(message):
        rules=[('Binary Flash frame length/footer','二进制响应帧受干扰或不完整，自动恢复未成功；已保留读取断点。'),
               ('OperationCancelled','操作已按停止请求结束，断点已保存。'),
               ('LUT','控制器命令表发生变化，已停止擦写，请重新探测设备。'),
               ('0->1','未擦除直接编程存在NOR的0→1限制；是否擦除由“写前擦除”单独控制，与跳过相同数据无关。'),
               ('disagree','多次读取结果不一致，已停止并保留断点。'),
               ('mismatch','校验结果不一致，已停止；详细参数见操作记录。'),
               ('Resume','续读文件与设备或参数不匹配，原文件已保留。'),
               ('Incomplete AT','串口响应不完整，请检查连接后续读或续写。'),
               ('busy','控制器长时间忙，操作已停止。'),
               ('WEL','写使能未成功，操作已停止。'),
               ('command error','设备返回写入命令错误，详情见操作记录。')]
        for key,text in rules:
            if key.lower() in message.lower():return text
        return message if re.search(r'[\u4e00-\u9fff]',message) else '后台操作失败，原始错误和参数已保存到操作记录。'

    def show_firmware_info(self):
        image = self.image
        if not image:
            self.fill_table(self.firmware_table, [('固件型号', '未选择'), ('主芯片', '未选择'), ('Flash 芯片', '未选择'),
                                                 ('固件大小', '未选择'), ('固件架构', '未选择'), ('固件版本', '未选择'),
                                                 ('SHA-256', '未选择'), ('IMEI', '未选择')])
            return
        imei = image.get('imei') or '未内置固定IMEI / 动态分配'
        label = '内置 IMEI' if image.get('imei') else ('匹配状态' if self.device_values.get('IMEI') else 'IMEI')
        kib_sz = image['size'] // 1024
        self.fill_table(self.firmware_table, [
            ('固件型号', image.get('model') or '未识别'),
            ('主芯片', image.get('soc') or 'ASR 平台芯片'),
            ('Flash 芯片', image.get('flash_chip') or f"{kib_sz} KiB ({image['size']/1048576:.2f} MiB) QSPI NOR"),
            ('固件大小', f"{image['size']:,} 字节 / {kib_sz} KiB ({image['size']/1048576:.2f} MiB)"),
            ('固件架构', 'HMIT 整机' if image['full_image'] else '局部 / 补丁'),
            ('固件版本', image['version']), ('SHA-256', image['sha256']), (label, imei)])

    def on_result(self, result):
        self.pending_result = result

    def on_finished(self):
        worker = self.worker
        result = self.pending_result or {'kind': worker.kind, 'success': False, 'error': '后台任务未返回结果'}
        self.worker = None
        worker.deleteLater()
        self.last_result = result
        kind = result['kind']
        if kind == 'probe':
            self.setting_probe = True
            scope = result.get('scope', 'all')
            selected = result.get('serial')
            if scope != 'web':
                self.port.clear()
                for row in result.get('ports', []):
                    port = row['port']
                    description = re.sub(r'\s*\(\s*'+re.escape(port)+r'\s*\)\s*$', '',
                                         row['description'], flags=re.IGNORECASE).strip()
                    self.port.addItem(f'{port} · {description}' if description else port, port)
                self.profile = selected
                self.refresh_read_partitions()
                if selected:
                    self.port.setCurrentIndex(self.port.findData(selected['port']))
                    capability = ('读写配置匹配' if selected['write_supported'] else
                                  '可读取，写入未匹配' if selected.get('read_supported') else 'AT 已连接，Flash 配置未匹配')
                    self.status(self.serial_light, selected['port']+' · '+capability, 'ok')
                    if selected.get('capability_error'):
                        self.append_log(selected['capability_error'])
                else:
                    self.port.setCurrentIndex(-1)
                    self.status(self.serial_light, '未找到可用的 ASR AT 端口', 'bad')
            web = result.get('web', {})
            if scope != 'serial':
                if web.get('success'):
                    for detected in result.get('web_devices', [web]):
                        found_ip = detected['ip']
                        if self.ip.findText(found_ip) < 0:
                            self.ip.addItem(found_ip, found_ip)
                    ip = web['ip']
                    index = self.ip.findText(ip)
                    if index < 0:
                        self.ip.addItem(ip, ip)
                        index = self.ip.count()-1
                    self.ip.setCurrentIndex(index)
                    self.status(self.web_light, ip+' · 登录成功', 'ok')
                    self.device_info.setText((web.get('model') or 'ASR 设备')+'\n'+(web.get('version') or ''))
                else:
                    self.status(self.web_light, '后台登录未通过；USB 通道状态见上方', 'bad')
                    self.append_log(web.get('error') or '未发现可用后台')
            if not hasattr(self, 'device_values'):
                self.device_values = {}
            if scope != 'web':
                self.device_values.update({
                    'Flash 容量': (f"{selected['flash_size']/1048576:g} MiB（映射回卷验证）"
                                   if selected and selected.get('flash_size') else
                                   '仅分区可读，整机长度未确认' if selected and selected.get('read_supported') else '未验证')})
            from asrcode.flash.asr_device_model import resolve_device_model
            if scope != 'serial':
                model = web.get('model') or (selected or {}).get('model') or resolve_device_model(values=self.device_values, image_info=self.image) or '未识别'
                self.device_values.update({'设备型号': model,
                                           '固件版本': web.get('version') or (selected or {}).get('version') or '未识别'})
            if scope != 'web':
                write_state = ('匹配，可读写' if selected and selected['write_supported'] else
                    '可读取；写入未匹配' if selected and selected.get('read_supported') else '未匹配')
                self.device_values['读写配置'] = write_state
                self.device_values['可写状态'] = write_state
                if selected:
                    if selected.get('soc'):
                        self.device_values['主芯片'] = selected['soc']
                    if selected.get('flash_chip'):
                        self.device_values['Flash 芯片'] = selected['flash_chip']
                if scope == 'serial':
                    ser_model = (selected or {}).get('model') or resolve_device_model(serial_info=selected, image_info=self.image)
                    self.device_values['设备型号'] = ser_model or '待 IP 获取'
                    self.device_values['固件版本'] = (selected or {}).get('version') or '未获取'
            if scope != 'serial':
                self.device_values['IMEI'] = web.get('imei') or '未获取'
                self.device_values['设备形态'] = web.get('device_type') or '未获取'
            if selected and selected.get('imei'):
                self.device_values['IMEI'] = selected['imei']
            self.fill_table(self.device_table, [(key, self.device_values.get(key, '待探测'))
                for key in ['设备型号', '主芯片', 'Flash 芯片', '固件版本', 'IMEI', 'Flash 容量', '设备形态', '可写状态']])
            self.setting_probe = False
            if self.image:
                self.show_firmware_info()
        if kind == 'power' and result.get('success'):
            self.profile = None
            self.refresh_read_partitions()
            act = result.get('action')
            label = '重启' if act == 'reboot' else ('关机' if act == 'poweroff' else '恢复出厂')
            mode_desc = '【AT模式】' if result.get('mode') == 'at' else '【URL模式】'
            self.append_log(f'{mode_desc}{label}指令已成功下发至设备。设备复位就绪后请重新检测设备。')
        if kind == 'at' and result.get('read_imei') and result.get('success') and not result.get('cancelled'):
            from asrcode.imei.reader import parse_imei
            imei=parse_imei(result['imei'])
            self.imei_input.setText(imei)
            self.device_values['IMEI']=imei
            self.fill_table(self.device_table,[(key,self.device_values.get(key,'待探测'))
                for key in ['设备型号','主芯片','Flash 芯片','固件版本','IMEI','Flash 容量','设备形态','可写状态']])
            self.append_log('IMEI读取成功，已回填输入框：'+imei)
        if kind == 'write_imei':
            if result.get('success'):
                self.status(self.task_light, 'IMEI写入完成', 'ok')
                new_imei = result.get('imei')
                if new_imei:
                    self.device_values['IMEI'] = new_imei
                    self.fill_table(self.device_table, [(key, self.device_values.get(key, '待探测'))
                        for key in ['设备型号', '主芯片', 'Flash 芯片', '固件版本', 'IMEI', 'Flash 容量', '设备形态', '可写状态']])
            else:
                self.status(self.task_light, 'IMEI写入结束', 'idle')
                if result.get('storage_verified'):
                    self.append_log('MRD已保存目标IMEI；运行时或模式恢复尚未确认，请查看修改记录后再决定是否重启。')
        if kind == 'inspect':
            self.image = result.get('image')
            if self.image:
                self.image_path.setText(self.image['path'])
                # textChanged invalidates first; assign the freshly checked result afterward.
                self.image = result['image']
                self.refresh_partition_modes()
                if self.image.get('partition_error'):
                    self.append_log('TIM 分区表无效，无法生成分区选项：'+self.image['partition_error'])
                self.status(self.image_light, f"{self.image['size']/1048576:g} MiB 整机镜像" if self.image['full_image'] else '局部镜像 / 非整机格式',
                            'ok' if self.image['full_image'] else 'idle')
                self.image_info.setText('大小：%s 字节\nSHA-256：%s' % (self.image['size'], self.image['sha256']))
                self.show_firmware_info()
            else:
                self.status(self.image_light, '镜像检查失败', 'bad')
        if result.get('cancelled'):
            self.status(self.task_light, '已停止，未标记完成', 'idle')
            if kind == 'read':
                self.read_action.setCurrentIndex(self.read_action.findData('resume'))
            self.task_info.setText('读取可校验续读；刷入请重新选择同一镜像继续。记录：'+result.get('run_dir', ''))
        elif kind == 'read' and result.get('details', {}).get('unverified_blocks'):
            details = result['details']
            self.status(self.task_light, '读取结束，存在未通过校验的数据块', 'bad')
            self.task_info.setText(f"{len(details['unverified_blocks'])} 个异常块已保留最后读数，文件不可作为已校验固件刷入。记录："+result.get('run_dir', ''))
        elif result.get('success'):
            self.status(self.task_light, '完成', 'ok')
            self.progress.setValue(100)
            details = result.get('details', {})
            if kind in ('read','write'):
                self.append_log(completion_summary(kind,details))
                digest=details.get('sha256') or details.get('readback_sha256')
                if digest:self.append_log('文件校验摘要 SHA-256：'+digest)
            self.task_info.setText(('校验 SHA-256：'+details.get('sha256', details.get('readback_sha256', ''))+'\n'
                                  if kind in ('read', 'write') else '')+'记录：'+result.get('run_dir', ''))
            if kind == 'read' and not details.get('verification', {}).get('matched', False):
                self.task_info.setText('读取完成；未完成全部数据复读校验，已记录文件 SHA-256。记录：'+result.get('run_dir', ''))
            if kind == 'write' and details.get('unchecked_resume_bytes'):
                self.task_info.setText(f"续写完成；{details['unchecked_resume_bytes']:,} 字节前缀未复核。本次后续块校验："+('开' if details.get('verification_performed') else '关')+'。记录：'+result.get('run_dir',''))
            elif kind == 'write' and not details.get('verification_performed', True):
                self.task_info.setText('写入命令已完成（未回读校验）。记录：'+result.get('run_dir', ''))
                self.append_log('写后校验未开启；此次完成不代表已核对 Flash 数据。')
            if kind == 'write':
                self.append_log('写入数据阶段已结束；设备重启后的运行状态尚未验证。')
            if kind == 'read':
                self.image_path.setText(self.output.text())
                self.append_log('读取完成；如需刷回，请点击“检查当前路径”。')
        else:
            self.status(self.task_light, '操作失败', 'bad')
            reason=result.get('error') or result.get('details',{}).get('error') or '请查看原始日志。'
            paths=[('刷入详情' if kind=='write' and label=='读取详情' else label,path) for label,path in diagnostic_paths(result)]
            locations='\n'.join(label+'：'+path for label,path in paths)
            self.task_info.setText(self.friendly_error(reason)+'\n原始错误：'+reason+'\n'+locations)
            self.append_log('操作未完成，原始错误：'+reason)
            for label,path in paths:self.append_log(label+'：'+path)
        self.refresh_enabled()

    def show_support(self):
        QMessageBox.information(self, '鼓励作者', '感谢使用！欢迎在 GitHub 仓库反馈问题。')

    def export_log(self):
        path, _ = QFileDialog.getSaveFileName(self, '保存界面日志', str(ROOT/'读刷日志.txt'), '文本文件 (*.txt)')
        if path:
            Path(path).write_text(self.log.toPlainText(), encoding='utf-8')

    def config_fields(self):
        return {'at_command':self.at_input, 'user': self.user, 'password': self.password, 'image_path': self.image_path,
                'output': self.output, 'offset': self.offset, 'imei': self.imei_input}

    def config_choices(self):
        return {'port': self.port, 'ip': self.ip, 'baudrate':self.baudrate, 'read_action': self.read_action,
                'read_range': self.read_range, 'mode': self.mode, 'power_mode': self.power_mode}

    def config_write_options(self):
        return {'backup': self.write_backup, 'verify': self.write_verify, 'skip_equal': self.write_skip_equal}

    def save_config(self, checked=False, notify=True):
        try:
            normal = self.normalGeometry() if self.isMaximized() else self.geometry()
            state = {'version': 1, 'layout_density': 'compact_20261027', 'geometry': bytes(self.saveGeometry().toBase64()).decode('ascii'),
                     'normal_geometry': [normal.x(),normal.y(),normal.width(),normal.height()],
                     'maximized': self.isMaximized(),
                     'splitter': bytes(self.splitter.saveState().toBase64()).decode('ascii'),
                     'splitter_sizes': self.splitter.sizes(),
                     'inputs': {name: field.text() for name,field in self.config_fields().items()},
                     'choices': {name: {'text': field.currentText(), 'data': field.currentData(),
                                       'index': field.currentIndex(),
                                       'items': [{'text':field.itemText(i),'data':field.itemData(i)}
                                                 for i in range(field.count())]}
                                 for name,field in self.config_choices().items()},
                     'log_wrap': self.wrap_log.isChecked(), 'log_timestamps': self.time_log.isChecked(),
                     'read_reread_verify': self.read_reread_verify.isChecked(),
                     'resume_check': self.resume_check.isChecked(),
                     'write_options': {name: control.isChecked() for name, control in self.config_write_options().items()},
                     'table_columns': {'device': [self.device_table.columnWidth(i) for i in range(3)],
                                       'firmware': [self.firmware_table.columnWidth(i) for i in range(3)]}}
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.config_path.with_suffix('.json.tmp')
            temporary.write_text(json.dumps(state,ensure_ascii=False,indent=2),encoding='utf-8')
            temporary.replace(self.config_path)
            if notify:
                self.append_log('配置已保存：'+str(self.config_path))
            return True
        except Exception as exc:
            self.append_log('保存配置失败：'+str(exc))
            return False

    def screen_adjust(self):
        configure_font(QApplication.instance(), self.windowHandle().screen() if self.windowHandle() else None)
        if not self.isMaximized():
            screen=self.windowHandle().screen() if self.windowHandle() else QApplication.primaryScreen()
            self.setGeometry(default_window_rect(screen.availableGeometry()))
        self.fit_to_screen()

    def fit_to_screen(self):
        screens = QApplication.screens()
        if not screens:return
        geometry = self.frameGeometry()
        screen = max(screens, key=lambda item: geometry.intersected(item.availableGeometry()).width()*geometry.intersected(item.availableGeometry()).height())
        area = screen.availableGeometry()
        if self.isMaximized():
            return
        frame=self.frameGeometry()
        bounded=bounded_frame(area,frame)
        extra_width=max(0,frame.width()-self.width())
        extra_height=max(0,frame.height()-self.height())
        self.resize(max(1,bounded.width()-extra_width),max(1,bounded.height()-extra_height))
        self.move(bounded.topLeft())

    def load_config(self):
        if not self.config_path.exists():
            return
        try:
            state = json.loads(self.config_path.read_text(encoding='utf-8'))
            self.setting_probe = True
            if type(state.get('resume_check')) is bool:
                self.resume_check.setChecked(state['resume_check'])
            if type(state.get('read_reread_verify')) is bool:
                self.read_reread_verify.setChecked(state['read_reread_verify'])
            for name, control in self.config_write_options().items():
                value = state.get('write_options', {}).get(name)
                if type(value) is bool:
                    control.setChecked(value)
            for name, field in self.config_choices().items():
                saved = state.get('choices',{}).get(name,{})
                if name == 'read_range' and saved:
                    self.preferred_read_range = saved.get('data', 'full')
                if name in ('port','ip') and saved.get('items'):
                    field.clear()
                    for item in saved['items']:
                        field.addItem(str(item['text']),item.get('data'))
                if saved:
                    index = field.findData(saved.get('data'))
                    if index < 0:
                        index = field.findText(saved.get('text',''))
                    if index >= 0:
                        field.setCurrentIndex(index)
                    if field.isEditable():
                        field.setEditText(saved.get('text',''))
            self.update_mode()
            for name, field in self.config_fields().items():
                if name in state.get('inputs',{}):
                    field.setText(str(state['inputs'][name]))
            self.wrap_log.setChecked(state.get('log_wrap',True))
            self.time_log.setChecked(state.get('log_timestamps',False))
            self.toggle_wrap()
            if state.get('geometry') and state.get('layout_density') == 'compact_20261027':
                self.restoreGeometry(QByteArray.fromBase64(state['geometry'].encode('ascii')))
            if state.get('splitter'):
                self.splitter.restoreState(QByteArray.fromBase64(state['splitter'].encode('ascii')))
            for key,table in [('device',self.device_table),('firmware',self.firmware_table)]:
                for column,width in enumerate(state.get('table_columns',{}).get(key,[])[:2]):
                    table.setColumnWidth(column,max(40,min(600,int(width))))
            self.fit_to_screen()
            self.append_log('已恢复窗口布局和输入配置；连接及镜像需重新验证。')
        except Exception as exc:
            self.append_log('配置恢复失败，使用默认值：'+str(exc))
        finally:
            self.setting_probe = False
            self.profile = None
            self.image = None
            self.refresh_enabled()

    def showEvent(self, event):
        super().showEvent(event)
        QTimer.singleShot(0, self.fit_to_screen)
        QTimer.singleShot(0, self.layout_log_toolbar)
        handle = self.windowHandle()
        if handle and not getattr(self, "_screen_hooked", False):
            handle.screenChanged.connect(lambda screen: self.screen_adjust())
            self._screen_hooked = True

    def closeEvent(self, event):
        if self.worker is not None:
            QMessageBox.information(self, '操作进行中', '请先停止并等待任务结束，再关闭窗口。')
            event.ignore()
            return
        self.save_config(notify=False)
        super().closeEvent(event)


def configure_font(app, screen=None):
    if not QFontDatabase().families():
        for name in ('msyh.ttc', 'arial.ttf'):
            path = Path(os.environ.get('WINDIR', 'C:/Windows'))/'Fonts'/name
            if path.exists():
                QFontDatabase.addApplicationFont(str(path))
    font=title_font()
    app.setFont(font)
    return font.pointSizeF()


def main():
    from asrcode.flash.dispatch import dispatch
    if dispatch():return
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    if hasattr(QApplication,'setHighDpiScaleFactorRoundingPolicy'):
        QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    configure_font(app)
    window = Window()
    window.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
