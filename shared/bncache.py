# shared with binary-jvm: not yet (new here, bncpp-22); keep language-neutral
"""A per-binary cache of slow analysis results: one JSON file per binary, with one section per result.

  next to the database     <x>.bndb.<tag>-cache.json   (tag: "bncpp"; binary-jvm would use its own)
  no database (yet)        <BN user directory>/<tag>/scratch/<sha256>.json   -- also when the database's folder
                           is not writable
  file                     {"sha256": <the binary's>, "<section>": {"version": n, ...}, ...}

The binary's sha256 (its raw bytes, as BN has them) keys the file, so a file of another binary is never used;
each section carries its producer's version (bump it when the producer changes). Delete the file to recompute.

Once the database is saved, the scratch file is copied next to it: by the GUI save hook (install_save_hook(),
UIContextNotification.OnAfterSaveFile) and, for saves BN does not report (scripts, bnrun --bndb-save), on the
next Cache() of that view.
"""
import hashlib
import json
import os
import shutil

import binaryninja


class Cache:
    def __init__(self, bv, tag="bncpp"):
        raw = bv.parent_view if bv.parent_view is not None else bv
        self.sha256 = hashlib.sha256(raw.read(raw.start, raw.length)).hexdigest()
        self.scratch = os.path.join(binaryninja.user_directory(), tag, "scratch", self.sha256 + ".json")
        self.sidecar = bv.file.filename + ".%s-cache.json" % tag if bv.file.has_database else None
        if self.sidecar is not None and not os.access(os.path.dirname(self.sidecar) or ".", os.W_OK):
            self.sidecar = None
        self.path = self.sidecar or self.scratch
        self.data = self._read(self.path)
        if self.sidecar is not None and not self.data:  # saved since the scratch file was written
            self.data = self._read(self.scratch)
            if self.data:
                self._write()

    def _read(self, path):
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return {}
        return data if data.get("sha256") == self.sha256 else {}

    def _write(self):
        self.data["sha256"] = self.sha256
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path + ".tmp", "w", encoding="utf-8") as fh:
            json.dump(self.data, fh)
        os.replace(self.path + ".tmp", self.path)

    def get(self, section, version):
        """the section's data, or None if missing or of another version"""
        s = self.data.get(section)
        return s if s is not None and s.get("version") == version else None

    def put(self, section, version, data):
        self.data[section] = dict(data, version=version)
        self._write()


def adopt_saved(bv, tag="bncpp"):
    """after a save: copy the scratch file next to the database (no-op when there is none or one exists)"""
    if not bv.file.has_database or not os.path.isdir(os.path.join(binaryninja.user_directory(), tag, "scratch")):
        return
    Cache(bv, tag)


def install_save_hook(tag="bncpp"):
    """GUI saves: adopt the scratch file once BN reports the save (no UI, e.g. headless: nothing to do)"""
    try:
        from binaryninjaui import UIContext, UIContextNotification
    except ImportError:
        return None

    class _SaveHook(UIContextNotification):
        def OnAfterSaveFile(self, context, file, frame):
            try:
                bv = frame.getCurrentBinaryView() if frame is not None else None
                if bv is not None:
                    adopt_saved(bv, tag)
            except Exception:  # a cache must never break a save
                import traceback
                traceback.print_exc()

    hook = _SaveHook()
    UIContext.registerNotification(hook)
    return hook
