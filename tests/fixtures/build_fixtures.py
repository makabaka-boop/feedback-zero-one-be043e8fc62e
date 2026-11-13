#!/usr/bin/env python3
"""Build the standalone binary fixtures under tests/fixtures/.

Everything here is hand-assembled from raw RFC 7541/9113 byte values; the
mature hpack library is deliberately not used, so the rejection and offset
tests stay independent of any third-party decoder.

Run:  python3 -I tests/fixtures/build_fixtures.py
"""

import os

HERE = os.path.dirname(os.path.abspath(__file__))

DATA = 0x0
HEADERS = 0x1
RST_STREAM = 0x3
CONTINUATION = 0x9
END_HEADERS = 0x4


def frame(ftype, flags, stream_id, payload):
    return (
        len(payload).to_bytes(3, "big")
        + bytes((ftype, flags))
        + stream_id.to_bytes(4, "big")
        + payload
    )


def write(name, blob):
    path = os.path.join(HERE, name)
    with open(path, "wb") as fh:
        fh.write(blob)
    print(f"{name}: {len(blob)} bytes")


def main():
    # --- valid_cross_frames.bin -------------------------------------------
    # Stream 1: one header block split over HEADERS + CONTINUATION.
    #   block = 40 01 78 01 61  (literal incremental: x: a)
    #         | be              (indexed 62 -> the entry just added)
    h = frame(HEADERS, 0, 1, bytes.fromhex("4001780161"))
    c = frame(CONTINUATION, END_HEADERS, 1, bytes.fromhex("be"))
    # Stream 3: complete one-frame block, same indexed field.
    h2 = frame(HEADERS, END_HEADERS, 3, bytes.fromhex("be"))
    # A DATA and RST_STREAM between further legal blocks are accepted then
    # ignored without clearing the dynamic table.
    d = frame(DATA, 0, 3, b"\x05hello")
    r = frame(RST_STREAM, 0, 3, (7).to_bytes(4, "big"))
    h3 = frame(HEADERS, END_HEADERS, 5, bytes.fromhex("82"))  # :method GET
    write("valid_cross_frames.bin", h + c + h2 + d + r + h3)

    # --- rej_continuation_eof.bin -----------------------------------------
    # Open block (HEADERS without END_HEADERS) followed immediately by EOF.
    write("rej_continuation_eof.bin",
          frame(HEADERS, 0, 1, b"\x82"))

    # --- rej_bad_index.bin ------------------------------------------------
    # Legal 10-byte block at offset 0, then indexed index 0 (illegal) in
    # the block starting at byte 10.
    good = frame(HEADERS, END_HEADERS, 1, b"\x82")
    bad = frame(HEADERS, END_HEADERS, 3, b"\x80")
    write("rej_bad_index.bin", good + bad)

    # --- rej_huffman_eos.bin ----------------------------------------------
    # Huffman string containing the 30-bit EOS symbol: FF FF FF C0.
    eos = bytes([0xFF, 0xFF, 0xFF, 0xC0])
    block = bytes([0x84]) + eos
    write("rej_huffman_eos.bin",
          frame(HEADERS, END_HEADERS, 1, block))

    # --- rej_unknown_frame.bin --------------------------------------------
    # A SETTINGS (type 4) frame at offset 0 must already have been removed.
    write("rej_unknown_frame.bin",
          (0).to_bytes(3, "big") + bytes((0x4, 0)) + (0).to_bytes(4, "big"))

    # --- rej_length_cap.bin -----------------------------------------------
    # Declared payload length 16385 exceeds the hard cap.
    write("rej_length_cap.bin",
          (16385).to_bytes(3, "big")
          + bytes((HEADERS, END_HEADERS)) + (1).to_bytes(4, "big"))


if __name__ == "__main__":
    main()
