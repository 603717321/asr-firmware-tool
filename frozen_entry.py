"""Portable frozen application entry; hardware-free release smoke test."""
import json
import os
from pathlib import Path
import sys
import ASR固件读刷工具 as reader

def main():
    if getattr(sys, 'frozen', False):
        root = Path(os.environ['LOCALAPPDATA']) if sys.platform == 'win32' else Path.home() / '.config'
        reader.ROOT = root / 'ASRFirmwareTool'
        reader.ROOT.mkdir(parents=True, exist_ok=True)
    if len(sys.argv) == 3 and sys.argv[1] == '--self-test':
        from serial.tools.list_ports import comports
        app = reader.QApplication([sys.argv[0]])
        window = reader.Window()
        window.show()
        app.processEvents()
        assert window.isVisible()
        assert window.read_range.ignore_closed_wheel and window.mode.ignore_closed_wheel
        Path(sys.argv[2]).write_text(json.dumps({'gui': True, 'ports': len(comports())}), encoding='utf-8')
        return
    reader.main()

if __name__ == '__main__':
    main()
