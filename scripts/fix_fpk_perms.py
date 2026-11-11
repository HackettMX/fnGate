#!/usr/bin/env python3
"""修正 .fpk 内的文件权限位，并重算 manifest 中的 checksum。

背景：fnpack 在 Windows 上打包时无法读取 Unix 执行位，产出的 tar 里
cmd/* 与二进制都是 0666，飞牛应用中心执行生命周期脚本时会失败。
本脚本在打包后重建两层 tar，显式设置 0755/0644，并同步更新
manifest 的 checksum（它等于 app.tgz 的 MD5）。

用法：python scripts/fix_fpk_perms.py <app.fpk>
"""
from __future__ import annotations

import hashlib
import io
import os
import re
import sys
import tarfile
import tempfile

EXEC_PREFIXES = ("cmd/", "bin/")
EXEC_NAMES = ("bin/fngate",)


def desired_mode(name: str, is_dir: bool) -> int:
    if is_dir:
        return 0o755
    base = name.lstrip("./")
    if base.startswith(EXEC_PREFIXES) or base in EXEC_NAMES:
        return 0o755
    return 0o644


def rebuild_inner_app_tgz(path: str) -> str:
    """重建 app.tgz，返回新的 md5。"""
    with tarfile.open(path, "r:gz") as src:
        members = src.getmembers()
        payload = []
        for m in members:
            data = src.extractfile(m).read() if m.isfile() else None
            payload.append((m, data))

    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as dst:
        for m, data in payload:
            info = tarfile.TarInfo(m.name)
            info.mode = desired_mode(m.name, m.isdir())
            info.mtime = m.mtime
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            if m.isdir():
                info.type = tarfile.DIRTYPE
                dst.addfile(info)
            elif data is not None:
                info.size = len(data)
                dst.addfile(info, io.BytesIO(data))

    blob = out.getvalue()
    with open(path, "wb") as fh:
        fh.write(blob)
    return hashlib.md5(blob).hexdigest()


def patch_manifest(raw: bytes, checksum: str) -> bytes:
    text = raw.decode("utf-8")
    text, count = re.subn(r"(?m)^checksum\s*=.*$", f"checksum                   = {checksum}", text)
    if count == 0:
        if not text.endswith("\n"):
            text += "\n"
        text += f"checksum                   = {checksum}\n"
    return text.encode("utf-8")


def rebuild_fpk(fpK_path: str) -> None:
    workdir = tempfile.mkdtemp(prefix="fpkfix-")
    with tarfile.open(fpK_path, "r:gz") as outer:
        order = [m.name for m in outer.getmembers()]
        try:
            # Python 3.12+ 的安全解包过滤器
            outer.extractall(workdir, filter="data")
        except TypeError:
            outer.extractall(workdir)

    app_tgz = os.path.join(workdir, "app.tgz")
    checksum = rebuild_inner_app_tgz(app_tgz)

    manifest_path = os.path.join(workdir, "manifest")
    with open(manifest_path, "rb") as fh:
        patched = patch_manifest(fh.read(), checksum)
    with open(manifest_path, "wb") as fh:
        fh.write(patched)

    tmp_out = fpK_path + ".tmp"
    with tarfile.open(tmp_out, "w:gz") as dst:
        for name in order:
            full = os.path.join(workdir, name)
            if not os.path.exists(full):
                continue

            def fix(info: tarfile.TarInfo, _name=name) -> tarfile.TarInfo:
                info.mode = desired_mode(_name, info.isdir())
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                return info

            dst.add(full, arcname=name, recursive=False, filter=fix)
    os.replace(tmp_out, fpK_path)

    import shutil

    shutil.rmtree(workdir, ignore_errors=True)
    print(f"fixed perms & checksum: {fpK_path} (app.tgz md5={checksum})")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: fix_fpk_perms.py <app.fpk>", file=sys.stderr)
        sys.exit(2)
    rebuild_fpk(sys.argv[1])
