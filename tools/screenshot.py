#!/usr/bin/env python3
"""
Zero OS 开发环境辅助脚本：截取当前桌面截图。

使用方式：
    python3 tools/screenshot.py --output /tmp/zero-os.png

选项：
    --output/-o  指定输出文件路径，默认保存到 ./screenshot.png

注意：
    - 在 macOS 上依赖系统自带的 `screencapture` 命令。
    - 如果首次运行被系统阻止，请前往“系统偏好设置 -> 安全性与隐私 -> 屏幕录制”授权终端。
"""

import argparse
import subprocess
from pathlib import Path


def capture(output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            ["screencapture", "-x", str(output)],
            check=True,
        )
        print(f"截图已保存到 {output}")
    except FileNotFoundError as exc:
        raise SystemExit("未找到 screencapture 命令，请确认在 macOS 环境运行。") from exc
    except subprocess.CalledProcessError as exc:
        raise SystemExit(f"截屏失败，返回码 {exc.returncode}。") from exc


def main() -> None:
    parser = argparse.ArgumentParser(description="Zero OS 截屏工具")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("screenshot.png"),
        help="输出文件路径（默认：./screenshot.png）",
    )
    args = parser.parse_args()
    capture(args.output)


if __name__ == "__main__":
    main()
