"""验证静态发布的内容指纹与首页引用，避免新旧资源混合。"""
import hashlib
import runpy
from pathlib import Path

import pytest


package = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/package_web.py"))["package"]


@pytest.mark.parametrize("fingerprint", [False, True])
def test_package_keeps_asset_bytes_and_updates_references(tmp_path, fingerprint):
    source = tmp_path / "source"
    source.mkdir()
    original = '<meta content="connect-src \'self\';"><link href="styles.css"><script src="app.js"></script>'
    (source / "index.html").write_text(original)
    for name, content in {"app.js": b"console.log('preview');", "styles.css": b"body {color: black}"}.items():
        (source / name).write_bytes(content)
    output = tmp_path / "public"
    manifest = package(source, output, "https://203.0.113.10:8443", fingerprint_assets=fingerprint)
    document = (output / "index.html").read_text()
    assert "connect-src 'self' https://203.0.113.10:8443;" in document
    assert (source / "index.html").read_text() == original
    assert len(manifest) == 4
    for name in ("app.js", "styles.css"):
        content = (source / name).read_bytes()
        asset = Path(name)
        expected = f"{asset.stem}.{hashlib.sha256(content).hexdigest()[:16]}{asset.suffix}" if fingerprint else name
        assert f'="{expected}"' in document
        assert (output / expected).read_bytes() == content
        assert manifest[expected]["sha256"] == hashlib.sha256(content).hexdigest()
    with pytest.raises(ValueError, match="输出目录已存在"):
        package(source, output, "https://203.0.113.10:8443", fingerprint_assets=fingerprint)
