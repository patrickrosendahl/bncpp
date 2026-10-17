# bncpp-56: refresh the scratch snapshot sample/synthv/<name>.bndb from synVbasic's save, with a PROVENANCE line.
#   python3 -I tests/refresh_synthv.py "for the bncpp-58 rounds repro"     [--src DIR] [--name synthv-studio.x86_64]
# Refuses while the bridge has our view of the snapshot open (a same-name view could be saved over it) or while the
# source is still being written (size / mtime change within a few seconds). The bncpp cache is copied only when the
# source's is newer than ours (our dry runs refresh ours).
import argparse, datetime, hashlib, os, shutil, subprocess, sys, time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BNRUN = "/Users/patrick/dev/bn-script-bridge/bnrun"


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
    views = subprocess.run([BNRUN, "--bndb-list"], capture_output=True, text=True, timeout=30).stdout.splitlines()
    if any(v.split("  ")[0] == dst for v in views):
        sys.exit("our view is open in BN: bnrun --bndb-close %s" % dst)
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
