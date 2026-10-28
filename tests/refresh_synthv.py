# bncpp-56: refresh the scratch snapshot sample/synthv/<name>.bndb from synVbasic's save, with a PROVENANCE line.
#   python3 -I tests/refresh_synthv.py "for the bncpp-58 rounds repro"     [--src DIR] [--name synthv-studio.x86_64]
# Refuses while a process has the snapshot open (a bnengine script holding its lock, or the app: lsof) or while the
# source is still being written (size / mtime change within a few seconds). The bncpp cache is copied only when the
# source's is newer than ours (our dry runs refresh ours).
import argparse, datetime, fcntl, hashlib, os, shutil, subprocess, sys, time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _holder(path):
    """Who has path open: a bnengine script (its flock, keyed as bnengine.lock_file does) or any process (lsof)"""
    lock = os.path.join(os.path.expanduser("~/.cache/bnengine/locks"),
                        hashlib.sha256(os.path.realpath(path).encode()).hexdigest()[:24] + ".lock")
    if os.path.exists(lock):
        with open(lock, "a+") as fh:
            try:
                fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                fh.seek(0)
                return "a bnengine script (pid %s)" % (fh.read().strip() or "?")
    if os.path.exists(path):
        pids = subprocess.run(["lsof", "-t", path], capture_output=True, text=True, timeout=30).stdout.split()
        if pids:
            return "pid " + ", ".join(pids)
    return None


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 24), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("reason")
    ap.add_argument("--src", default="/Users/patrick/rev/synVbasic/work")
    ap.add_argument("--name", default="synthv-studio.x86_64")
    args = ap.parse_args()
    dst_dir = os.path.join(REPO, "sample/synthv")
    src, dst = (os.path.join(d, args.name + ".bndb") for d in (args.src, dst_dir))
    holder = _holder(dst)
    if holder:
        sys.exit("%s is open (%s): close it first" % (dst, holder))
    st = os.stat(src)
    time.sleep(5)
    st2 = os.stat(src)
    if (st.st_size, st.st_mtime) != (st2.st_size, st2.st_mtime):
        sys.exit("%s is still being written" % src)
    shutil.copy2(src, dst)
    digest = _sha256(dst)
    if digest != _sha256(src):
        sys.exit("copy differs from %s" % src)
    copied = [".bndb"]
    cache = ".bndb.bncpp-cache.json"
    if os.path.exists(src[:-5] + cache) and (not os.path.exists(dst[:-5] + cache)
                                             or os.path.getmtime(src[:-5] + cache) > os.path.getmtime(dst[:-5] + cache)):
        shutil.copy2(src[:-5] + cache, dst[:-5] + cache)
        copied.append("bncpp cache")
    saved = datetime.datetime.fromtimestamp(st.st_mtime).strftime("%H:%M")
    line = "%s: %s refreshed from synVbasic's %s save (sha256 %s...); %s.\n" % (
        datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), " + ".join(copied), saved, digest[:16], args.reason)
    with open(os.path.join(dst_dir, "PROVENANCE.txt"), "a", encoding="utf-8") as fh:
        fh.write(line)
    print(line, end="")


if __name__ == "__main__":
    main()
