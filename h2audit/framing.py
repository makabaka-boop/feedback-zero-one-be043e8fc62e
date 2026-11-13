"""RFC 9113 section 4 / 6 framing validation.

The input is the raw frame payload of one connection, one direction, with
the connection preface and all SETTINGS frames already removed.  Only
HEADERS (0x1), CONTINUATION (0x9), DATA (0x0) and RST_STREAM (0x3) frames
may appear.

Validation scope (deliberately limited per the task):

* frame length, stream identifier, padding and priority *skeleton* only;
* unknown flags and the R reserved bit are ignored;
* stream state, HTTP semantics and flow control are not checked;
* padding bytes themselves are arbitrary and never inspected.

Two passes are effectively performed while scanning: every frame of the
file is validated first, and header blocks are extracted at the same time.
HPACK decoding only starts after the whole file has been accepted.
"""

from dataclasses import dataclass

# Frame types (RFC 9113 section 11.2).
DATA = 0x0
HEADERS = 0x1
RST_STREAM = 0x3
CONTINUATION = 0x9
_ALLOWED_TYPES = frozenset((DATA, HEADERS, RST_STREAM, CONTINUATION))

# Frame flags.
END_STREAM = 0x1
ACK = 0x1
END_HEADERS = 0x4
PADDED = 0x8
PRIORITY = 0x20

FRAME_HEADER_LEN = 9
# The hard cap from the task: every frame's 3-byte length must stay at or
# below 16384 (SETTINGS_MAX_FRAME_SIZE is not negotiated in this input).
MAX_FRAME_PAYLOAD = 16384

STREAM_ID_MASK = 0x7FFFFFFF


class FramingError(Exception):
    """A framing violation.

    ``offset`` is the zero-based byte offset where the offending frame
    starts, except for an end-of-file while waiting for a CONTINUATION,
    where it is the start of the block's HEADERS frame.
    """

    def __init__(self, message: str, offset: int):
        super().__init__(f"{message} at byte {offset}")
        self.offset = offset


@dataclass
class HeaderBlock:
    stream_id: int
    offset: int          # zero-based start of the first (HEADERS) frame
    payload: bytes       # concatenated, padding/priority-stripped block


def _read_frame_header(data: bytes, pos: int):
    """Return (length, ftype, flags, stream_id, payload_start)."""
    if len(data) - pos < FRAME_HEADER_LEN:
        raise FramingError("truncated frame header", pos)
    length = int.from_bytes(data[pos:pos + 3], "big")
    ftype = data[pos + 3]
    flags = data[pos + 4]
    stream_id = int.from_bytes(data[pos + 5:pos + 9], "big") & STREAM_ID_MASK
    return length, ftype, flags, stream_id, pos + FRAME_HEADER_LEN


def _check_payload_complete(data: bytes, pos: int, length: int):
    if len(data) - pos < length:
        raise FramingError(
            f"truncated frame payload: need {length} bytes, "
            f"have {len(data) - pos}",
            pos - FRAME_HEADER_LEN,
        )


def _strip_headlers_fragment(payload: bytes, flags: int, frame_offset: int):
    """Validate padding / priority skeleton of a HEADERS frame.

    Returns the actual header block fragment with the pad-length field,
    padding bytes and (possibly present) priority section removed.
    """
    fragment = payload
    if flags & PADDED:
        if len(fragment) < 1:
            raise FramingError(
                "PADDED HEADERS frame missing pad length field", frame_offset
            )
        pad_length = fragment[0]
        if pad_length >= len(fragment):
            raise FramingError(
                "padding length exceeds HEADERS frame payload", frame_offset
            )
        fragment = fragment[1:len(fragment) - pad_length]
    if flags & PRIORITY:
        # E (1 bit), stream dependency (31 bits), weight (1 byte) = 5 bytes.
        if len(fragment) < 5:
            raise FramingError(
                "PRIORITY HEADERS frame missing 5-byte priority section",
                frame_offset,
            )
        fragment = fragment[5:]
    return fragment


def split_header_blocks(data: bytes):
    """Scan *data* and return the ordered list of :class:`HeaderBlock`.

    Raises :class:`FramingError` on the first violation; the reported
    offset is the start of the offending frame, except for an EOF inside
    an unfinished block which reports the block's HEADERS start.
    """
    blocks = []
    pos = 0
    in_block = False
    block_stream = 0
    block_start = 0
    block_parts = []

    while pos < len(data):
        frame_offset = pos
        length, ftype, flags, stream_id, payload_start = _read_frame_header(
            data, pos
        )
        if length > MAX_FRAME_PAYLOAD:
            raise FramingError(
                f"frame length {length} exceeds {MAX_FRAME_PAYLOAD}",
                frame_offset,
            )
        _check_payload_complete(data, payload_start, length)
        payload = data[payload_start:payload_start + length]
        next_pos = payload_start + length

        if ftype not in _ALLOWED_TYPES:
            raise FramingError(
                f"unexpected frame type 0x{ftype:02x}", frame_offset
            )

        if in_block:
            # An unfinished header block may only be followed by
            # CONTINUATION frames on the same stream; END_STREAM never ends
            # a block, only END_HEADERS does.
            if ftype != CONTINUATION:
                raise FramingError(
                    "unfinished header block must be followed by "
                    "CONTINUATION",
                    frame_offset,
                )
            if stream_id != block_stream:
                raise FramingError(
                    "CONTINUATION stream identifier does not match the "
                    "HEADERS frame",
                    frame_offset,
                )
            block_parts.append(payload)
            if flags & END_HEADERS:
                blocks.append(
                    HeaderBlock(
                        block_stream, block_start, b"".join(block_parts)
                    )
                )
                in_block = False
                block_parts = []
            pos = next_pos
            continue

        if ftype == CONTINUATION:
            raise FramingError(
                "CONTINUATION frame without a matching HEADERS frame",
                frame_offset,
            )

        if stream_id == 0:
            raise FramingError(
                f"frame type 0x{ftype:02x} on stream 0 is not allowed",
                frame_offset,
            )

        if ftype == DATA:
            if flags & PADDED:
                if len(payload) < 1:
                    raise FramingError(
                        "PADDED DATA frame missing pad length field",
                        frame_offset,
                    )
                pad_length = payload[0]
                if pad_length >= len(payload):
                    raise FramingError(
                        "padding length exceeds DATA frame payload",
                        frame_offset,
                    )
            # Validated, then ignored; DATA never touches the HPACK table.
            pos = next_pos
            continue

        if ftype == RST_STREAM:
            if length != 4:
                raise FramingError(
                    f"RST_STREAM payload must be exactly 4 bytes, got "
                    f"{length}",
                    frame_offset,
                )
            # Validated, then ignored; RST_STREAM never touches the table.
            pos = next_pos
            continue

        # ftype == HEADERS
        fragment = _strip_headlers_fragment(payload, flags, frame_offset)
        block_stream = stream_id
        block_start = frame_offset
        block_parts = [fragment]
        if flags & END_HEADERS:
            blocks.append(
                HeaderBlock(stream_id, frame_offset, b"".join(block_parts))
            )
            block_parts = []
        else:
            in_block = True
        pos = next_pos

    if in_block:
        # EOF while the block is still open: report the HEADERS start.
        raise FramingError(
            "end of file while waiting for CONTINUATION", block_start
        )

    return blocks
