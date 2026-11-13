"""Helpers for building RFC 9113 frame files in tests."""

DATA = 0x0
HEADERS = 0x1
RST_STREAM = 0x3
CONTINUATION = 0x9

END_STREAM = 0x1
END_HEADERS = 0x4
PADDED = 0x8
PRIORITY = 0x20


def frame(ftype, flags, stream_id, payload, reserved=0):
    length = len(payload)
    assert length <= 0xFFFFFF
    sid = (reserved & 1) << 31 | (stream_id & 0x7FFFFFFF)
    return (
        length.to_bytes(3, "big")
        + bytes((ftype, flags))
        + sid.to_bytes(4, "big")
        + payload
    )


def headers(stream_id, block, flags=END_HEADERS, pad=None,
            priority=None, reserved=0):
    payload = b""
    fl = flags
    if pad is not None:
        fl |= PADDED
        payload += bytes((pad,))
    if priority is not None:
        fl |= PRIORITY
        payload += priority
    payload += block
    if pad is not None:
        payload += b"\x00" * pad
    return frame(HEADERS, fl, stream_id, payload, reserved)


def continuation(stream_id, fragment, flags=END_HEADERS, reserved=0):
    return frame(CONTINUATION, flags, stream_id, fragment, reserved)


def data_frame(stream_id, payload=b"", flags=0, pad=None, reserved=0):
    data = b""
    fl = flags
    if pad is not None:
        fl |= PADDED
        data += bytes((pad,))
    data += payload
    if pad is not None:
        data += b"\xab" * pad
    return frame(DATA, fl, stream_id, data, reserved)


def rst(stream_id, error_code=0, reserved=0):
    return frame(RST_STREAM, 0, stream_id,
                 error_code.to_bytes(4, "big"), reserved)
