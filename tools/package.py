#!/usr/bin/env python3
"""Build <app>-<version>.tgz with clean permissions, without local/, caches or compiled files."""
import os
import sys
import tarfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXCLUDE_DIRS = {"local", "__pycache__", ".pytest_cache"}


def main(app, version):
    src = os.path.join(ROOT, app)
    out = os.path.join(ROOT, "%s-%s.tgz" % (app, version))

    def filt(ti):
        parts = ti.name.split("/")
        if any(p in EXCLUDE_DIRS for p in parts) or ti.name.endswith((".pyc", ".DS_Store")):
            return None
        ti.uid = ti.gid = 0
        ti.uname = ti.gname = ""
        if ti.isdir():
            ti.mode = 0o755
        else:
            ti.mode = 0o755 if (parts[1:2] == ["bin"] and ti.name.endswith((".py", ".sh"))) else 0o644
        return ti

    with tarfile.open(out, "w:gz") as tar:
        tar.add(src, arcname=app, filter=filt)
    print("built %s (%.1f KB)" % (out, os.path.getsize(out) / 1024))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
