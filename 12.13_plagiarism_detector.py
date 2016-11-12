#!/usr/local/bin/python
from __future__ import print_function

import sys
import os
import os.path
import time

def get_suspicious_pairs(k, strs):
    names = [s[0] for s in strs]
    files = [s[1] for s in strs]
    suspects = []
    tbl = {}
    for i,f in enumerate(files):
        sys.stderr.write('.'); sys.stderr.flush()
        if len(f) < k: continue
        for offset in range(len(f) - k +1):
            segment = f[offset:offset+k]
            if segment in tbl:
                other = tbl[segment]
                if other[0] != i:
                    suspects.append(
                        ("%s:%s" % (names[other[0]], other[1]), "%s:%s" % (names[i], offset))
                    )
                    break
            tbl[segment] = (i, offset)
    print("\n", file=sys.stderr)
    return suspects


def get_line_and_offset(path_and_offset):
    path, abs_offset = path_and_offset.split(":")
    abs_offset = int(abs_offset)

    f = open(path)
    accum_len = 0
    for lineno, line in enumerate(f.readlines()):
        accum_len += len(line)
        if accum_len >= abs_offset: break
    accum_len -= len(line)
    inline_offset = abs_offset - accum_len
    return "%s:%s+%s" % (path, lineno+1, inline_offset+1)


def main(root_dir, k, suffix):
    files = []
    t0 = time.time()
    for dirpath, dirnames, filenames in os.walk(root_dir):
        for filename in [f for f in filenames if f.endswith(suffix)]:
            path = os.path.join(dirpath, filename)
            files.append(open(path))

    strs = [(f.name, f.read()) for f in files]
    [f.close() for f in files]
    t1 = time.time()
    print("Collected %s files with suffix '%s'; took %.2fsecs" % (len(files), suffix, t1-t0))

    t0 = time.time()
    suspicious = get_suspicious_pairs(k, strs)
    t1 = time.time()
    print("Done processing; took %.2fsecs. Found %s  %s-suspicious file pairs:" % (t1-t0, len(suspicious), k) )
    for s1, s2 in suspicious:
        print("    %s  AND  %s" % (get_line_and_offset(s1), get_line_and_offset(s2)))



if __name__ == "__main__":
    main(sys.argv[1], int(sys.argv[2]), sys.argv[3])

