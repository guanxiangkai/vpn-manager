#!/usr/bin/env python3
"""生成仅含公开静态资源的 OSS 上传目录；不接收任何账户秘密。"""
import argparse
import hashlib
import html
import json
from pathlib import Path
import shutil
from urllib.parse import urlsplit


def package(source: Path, destination: Path, api_origin: str) -> dict:
    parsed = urlsplit(api_origin)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
        raise ValueError("API 必须是无凭据、无路径的 HTTPS 来源")
    _ = parsed.port
    origin = f"https://{parsed.netloc}"
    # URL 配置同时进入 CSP，限制为主机名、IP 和端口字符，禁止注入策略。
    if any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.:-[]" for character in parsed.netloc):
        raise ValueError("API 主机或端口无效")
    if destination.exists():
        raise ValueError("输出目录已存在，拒绝覆盖")
    document = (source / "index.html").read_text(encoding="utf-8")
    before = "connect-src 'self';"
    if document.count(before) != 1:
        raise ValueError("页面 CSP 模板不唯一")
    document = document.replace(before, f"connect-src 'self' {html.escape(origin, quote=True)};")
    destination.mkdir(parents=True)
    (destination / "index.html").write_text(document, encoding="utf-8")
    for name in ("app.js", "styles.css"):
        shutil.copyfile(source / name, destination / name)
    (destination / "config.json").write_text(json.dumps({"apiBaseUrl": origin, "sessionTransport": "bearer"}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {item.name: {"bytes": item.stat().st_size, "sha256": hashlib.sha256(item.read_bytes()).hexdigest()} for item in sorted(destination.iterdir())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-origin", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(package(Path(__file__).resolve().parents[1] / "web", args.output, args.api_origin), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
