# ASR固件读刷工具

ASR 设备固件读取与刷入工具。

## 下载

查看 [最新发布](https://github.com/603717321/asr-firmware-tool/releases/tag/continuous) 或选择对应平台：

| 平台 | 下载 |
|---|---|
| Windows x64（Python 3.8 / Qt 5.15.2 兼容构建） | [EXE](https://github.com/603717321/asr-firmware-tool/releases/download/continuous/ASR-Firmware-Tool-windows-x64.exe) |
| Linux x64（Ubuntu 22.04 构建） | [tar.gz](https://github.com/603717321/asr-firmware-tool/releases/download/continuous/ASR-Firmware-Tool-linux-x64.tar.gz) |
| macOS Apple Silicon | [tar.gz](https://github.com/603717321/asr-firmware-tool/releases/download/continuous/ASR-Firmware-Tool-macos-arm64.tar.gz) |

Linux 和 macOS 解压后，在终端运行目录里的 `./ASR-Firmware-Tool`。台式环境需要 Qt 所需的系统图形库；串口需要系统识别设备并授予访问权限。自动构建只验证窗口启动、串口枚举和后台入口。Linux/macOS 尚未做设备读刷验证，自动发现后台网关仍以 Windows 为主；在其他系统可手填设备地址。Windows 7 SP1 是兼容目标，需要系统运行库更新和设备驱动，尚无真机测试。macOS 构建未作 Apple 公证。

## 源码运行

```sh
python -m pip install -r requirements.txt
python "ASR固件读刷工具.py"
```

## 自动构建

[构建记录](https://github.com/603717321/asr-firmware-tool/actions)：推送或提交拉取请求会构建各平台产物。默认分支的三个构建均通过后更新连续发布；首次运行完成前下载链接尚无文件。可通过 SHA256SUMS.txt 核对文件。

