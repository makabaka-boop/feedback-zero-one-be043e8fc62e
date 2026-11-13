"""h2audit - RFC 9113 single-connection, single-direction frame auditor.

Only the frame types listed in the task scope (HEADERS, CONTINUATION, DATA,
RST_STREAM) are accepted.  The connection preface and SETTINGS frames have
already been removed from the input by the caller.
"""

from .framing import FramingError, split_header_blocks
from .hpack import HpackError, decode_block, Decoder

__all__ = [
    "FramingError",
    "HpackError",
    "split_header_blocks",
    "decode_block",
    "Decoder",
    "audit",
]


def audit(data: bytes):
    """Validate *data* completely, then decode every header block.

    Returns a list of ``[stream_id, offset, fields]`` arrays in HEADERS
    appearance order.  Either the whole input is accepted or a
    :class:`FramingError` / :class:`HpackError` is raised and nothing is
    returned (all-or-nothing rejection).
    """
    blocks = split_header_blocks(data)
    decoder = Decoder()
    result = []
    for block in blocks:
        fields = decoder.decode_block(block.payload, block.offset)
        result.append([block.stream_id, block.offset, fields])
    return result
