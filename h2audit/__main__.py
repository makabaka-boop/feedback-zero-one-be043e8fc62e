"""Command line entry point.

Usage::

    python3 -m h2audit FRAME_FILE [-o OUTPUT_JSON]

On success OUTPUT_JSON is replaced atomically (a temporary file in the same
directory is written and then ``os.replace``d).  On any validation error the
process exits non-zero with a diagnostic on stderr and the previous output
file (if any) is left untouched.  With ``-o -`` or without ``-o`` the JSON
is written to stdout.
"""

import argparse
import json
import os
import sys
import tempfile

from .framing import FramingError
from .hpack import HpackError
from . import audit


def _atomic_write_json(path: str, text: str) -> None:
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp_path = tempfile.mkstemp(prefix=".h2audit-", suffix=".tmp",
                                    dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        raise


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m h2audit",
        description="Collect HTTP/2 headers from a pre-processed, "
                    "single-connection single-direction frame file.",
    )
    parser.add_argument("frame_file",
                        help="raw frame file (preface and SETTINGS removed)")
    parser.add_argument("-o", "--output", default="-",
                        help="JSON output path ('-' for stdout, default)")
    args = parser.parse_args(argv)

    with open(args.frame_file, "rb") as fh:
        data = fh.read()

    try:
        result = audit(data)
    except (FramingError, HpackError) as exc:
        print(f"h2audit: rejected: {exc}", file=sys.stderr)
        return 1

    text = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
    if args.output == "-":
        print(text)
    else:
        _atomic_write_json(args.output, text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
