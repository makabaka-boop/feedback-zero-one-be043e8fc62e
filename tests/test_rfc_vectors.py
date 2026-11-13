"""RFC 7541 Appendix C style vector tests using embedded byte sequences.

The encoded block is generated once from the standard Appendix C.4 request
header set (with Huffman coding) and pinned here as raw bytes, so the test
itself needs no third-party encoder and proves the Huffman path against a
documented, well-known header set.
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from h2audit.hpack import Decoder, HpackError  # noqa: E402

# Encoding of the Appendix C.4 request header set, Huffman enabled.
RFC_C4_HUFFMAN_BLOCK = bytes.fromhex(
    "828684418cf1e3c2e5f23a6ba0ab90f4ff"
    "5886a8eb10649cbf"
    "408825a849e95ba97d7f"
    "8925a849e95bb8e8b4bf"
)

RFC_C4_HEADERS = [
    (b":method", b"GET"),
    (b":scheme", b"http"),
    (b":path", b"/"),
    (b":authority", b"www.example.com"),
    (b"cache-control", b"no-cache"),
    (b"custom-key", b"custom-value"),
]


class RfcVectorTests(unittest.TestCase):

    def test_appendix_c4_huffman_request(self):
        out = Decoder().decode_block(RFC_C4_HUFFMAN_BLOCK, 0)
        self.assertEqual(
            out,
            [[n.hex(), v.hex()] for n, v in RFC_C4_HEADERS],
        )

    def test_static_indexes_cover_appendix_a_values(self):
        dec = Decoder()
        # Spot-check a spread of Appendix A static entries.
        cases = {
            1: (b":authority", b""),
            2: (b":method", b"GET"),
            8: (b":status", b"200"),
            16: (b"accept-encoding", b"gzip, deflate"),
            31: (b"content-type", b""),
            61: (b"www-authenticate", b""),
        }
        for index, (name, value) in cases.items():
            out = dec.decode_block(bytes([0x80 | index]), 0)
            self.assertEqual(out, [[name.hex(), value.hex()]])

    def test_index_62_is_not_static(self):
        # The static table has exactly 61 entries; 62 needs a dynamic entry.
        with self.assertRaises(HpackError):
            Decoder().decode_block(b"\xbe", 0)

    def test_huffman_roundtrip_of_ascii(self):
        # A longer all-ASCII string exercises many Huffman codes.
        text = (b"www.example.com/customers/12345/interactions/"
                b"jane-doe/relate-procedure")
        # literal without indexing, new name "k", Huffman value <text>
        block = b"\x00\x01k" + _huffman_literal(text)
        out = Decoder().decode_block(block, 0)
        self.assertEqual(out, [["6b", text.hex()]])


def _huffman_literal(raw: bytes) -> bytes:
    from h2audit.tables import HUFFMAN_TABLE
    bits = 0
    nbits = 0
    for byte in raw:
        code, length = HUFFMAN_TABLE[byte]
        bits = (bits << length) | code
        nbits += length
    pad = (8 - nbits % 8) % 8
    bits = (bits << pad) | ((1 << pad) - 1)  # all-ones EOS prefix padding
    nbits += pad
    encoded = bits.to_bytes(nbits // 8, "big")
    # 7-bit-prefixed length with the Huffman flag set.
    length_enc = _encode_integer(len(encoded), 7)
    prefix = bytes([length_enc[0] | 0x80]) + length_enc[1:]
    return prefix + encoded


def _encode_integer(value: int, prefix_bits: int) -> bytes:
    mask = (1 << prefix_bits) - 1
    if value < mask:
        return bytes([value])
    out = [mask]
    value -= mask
    while value >= 128:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


if __name__ == "__main__":
    unittest.main()
