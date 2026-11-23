"""Build a native distribution, then verify GUI startup and worker imports."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('target', choices=('windows-x64','linux-x64','macos-arm64'))
    target = parser.parse_args().target
    root = Path(__file__).resolve().parent
    os.chdir(root)
    name = 'ASR-Firmware-Tool'
    windows = sys.platform == 'win32'
    command = [sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean', '--noupx',
               '--name', name, '--collect-submodules', 'asrcode',
               '--collect-submodules', 'serial',
               *(['--onefile','--windowed'] if windows else ['--onedir']), 'frozen_entry.py']
    subprocess.run(command, check=True)
    bundle = root / 'dist' / (name + ('.exe' if windows else ''))
    artifact = root / 'artifacts'
    artifact.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='asr-release-') as tmp:
        stage = Path(tmp)
        if windows:
            exe = stage / bundle.name
            shutil.copy2(bundle, exe)
        else:
            shutil.copytree(bundle, stage / name, symlinks=True)
            exe = stage / name / name
        env = {k:v for k,v in os.environ.items() if k not in ('PYTHONPATH','PYTHONHOME')}
        env.update(QT_QPA_PLATFORM='offscreen', LOCALAPPDATA=tmp, HOME=tmp)
        report = stage / 'check.json'
        subprocess.run([str(exe), '--self-test', str(report)], cwd=stage, env=env, timeout=90, check=True)
        assert json.loads(report.read_text(encoding='utf-8'))['gui']
        for module in ('at_flash_backup', 'direct_flash'):
            test = subprocess.run([str(exe), '-m', 'asrcode.flash.'+module, '--help'],
                                  cwd=stage, env=env, capture_output=True, timeout=90, check=True)
            assert b'usage:' in test.stdout, module
    if windows:
        shutil.copy2(bundle, artifact / (name+'-'+target+'.exe'))
    else:
        shutil.make_archive(str(artifact / (name+'-'+target)), 'gztar', bundle.parent, bundle.name)

if __name__ == '__main__':
    main()
