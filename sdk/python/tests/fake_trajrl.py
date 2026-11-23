"""A stand-in for trajrl in the tests.

Each run appends one JSON line to $FAKE_TRAJRL_LOG: its argv, its
TRAJRL_PASSPHRASE_FILE, whether stdin was /dev/null, and what stdin held.
It answers from $FAKE_TRAJRL_ANSWERS, a JSON object keyed by the argv
joined with one space:

    {"stdout": TEXT, "lines": [OBJ, ...], "stderr": TEXT, "exit": N,
     "echo_stdin": true, "write": {"path": P, "data": TEXT}, "sleep": S}

lines are printed one JSON object a line (NDJSON); echo_stdin adds a
{"stdout": base64(stdin)} line before them. An argv with no answer is a
usage error, said the way trajrl --json says one.
"""

import base64
import json
import os
import sys
import time


def stdin_is_devnull():
    try:
        st, null = os.fstat(0), os.stat(os.devnull)
    except OSError:
        return False
    return (st.st_dev, st.st_ino) == (null.st_dev, null.st_ino)


def main():
    argv = sys.argv[1:]
    devnull = stdin_is_devnull()
    stdin = b"" if devnull else sys.stdin.buffer.read()
    with open(os.environ["FAKE_TRAJRL_LOG"], "a") as log:
        log.write(json.dumps({
            "argv": argv,
            "passphrase_file": os.environ.get("TRAJRL_PASSPHRASE_FILE"),
            "stdin_devnull": devnull,
            "stdin": stdin.decode("utf-8", "replace"),
        }) + "\n")
    with open(os.environ["FAKE_TRAJRL_ANSWERS"]) as f:
        answers = json.load(f)
    a = answers.get(" ".join(argv))
    if a is None:
        sys.stderr.write(json.dumps({"error": "fake trajrl: no answer for %r" % argv, "code": "usage"}) + "\n")
        return 2
    if a.get("sleep"):
        time.sleep(a["sleep"])
    if a.get("write"):
        with open(a["write"]["path"], "w") as f:
            f.write(a["write"]["data"])
    out = sys.stdout
    if a.get("echo_stdin"):
        out.write(json.dumps({"stdout": base64.b64encode(stdin).decode()}) + "\n")
    for line in a.get("lines", []):
        out.write(json.dumps(line) + "\n")
        out.flush()
    out.write(a.get("stdout", ""))
    out.flush()
    sys.stderr.write(a.get("stderr", ""))
    return a.get("exit", 0)


if __name__ == "__main__":
    sys.exit(main())
