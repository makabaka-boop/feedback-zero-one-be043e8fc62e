"""Acceptance tests.

* Legal HPACK blocks are compared against the mature ``hpack`` library
  (imported from an explicit path, so the suite still runs under
  ``python3 -I``).  The production package itself never imports it.
* Rejection behaviour and byte offsets use independent, hand-built
  fixtures in this file (no third-party decoder involved).
"""

import os
import random
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))

from frame_builder import (  # noqa: E402
    headers, continuation, data_frame, rst, END_STREAM,
)
from h2audit import audit  # noqa: E402
from h2audit.framing import FramingError  # noqa: E402
from h2audit.hpack import HpackError  # noqa: E402

# Mature reference implementation, used for comparison only.
sys.path.insert(0, "/home/node/.local/lib/python3.11/site-packages")
try:
    from hpack.hpack import Decoder as RefDecoder, Encoder as RefEncoder
    HAVE_HPACK = True
except ImportError:  # pragma: no cover - environment without the library
    HAVE_HPACK = False


def encode_integer(value, prefix_bits):
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


def encode_string(raw: bytes, huffman: bool) -> bytes:
    if huffman:
        from hpack.huffman import HuffmanEncoder
        from hpack.huffman_constants import REQUEST_CODES, \
            REQUEST_CODES_LENGTH
        enc = HuffmanEncoder(REQUEST_CODES, REQUEST_CODES_LENGTH)
        encoded = enc.encode(raw)
        length = encode_integer(len(encoded), 7)
        return bytes([length[0] | 0x80]) + length[1:] + encoded
    return encode_integer(len(raw), 7) + raw


def size_update(new_size):
    # 001xxxxx with a 5-bit integer prefix.
    encoded = encode_integer(new_size, 5)
    return bytes([0x20 | encoded[0]]) + encoded[1:]


def literal_incremental(name, value, huffman):
    return (b"\x40" + encode_string(name, huffman)
            + encode_string(value, huffman))


def literal_unindexed(name, value, huffman):
    return (b"\x00" + encode_string(name, huffman)
            + encode_string(value, huffman))


def split_into_frames(stream_id, block, rng, h0_flags=0):
    """Spread *block* over one HEADERS + zero+ CONTINUATION frames."""
    if not block:
        return headers(stream_id, block)
    cut = rng.randrange(1, len(block) + 1)
    first, rest = block[:cut], block[cut:]
    frames = headers(stream_id, first, flags=h0_flags)
    while rest:
        cut = rng.randrange(1, len(rest) + 1)
        frag, rest = rest[:cut], rest[cut:]
        frames += continuation(stream_id, frag,
                               flags=0 if rest else 4)
    return frames


@unittest.skipUnless(HAVE_HPACK, "reference hpack library not installed")
class ReferenceComparisonTests(unittest.TestCase):
    """Our decoder must agree with hpack.Decoder on legal input."""

    def setUp(self):
        self.rng = random.Random(20261113)
        # Byte vocabulary includes high bytes and Huffman-heavy ASCII.
        vocab = bytes(range(0, 256))
        self.names = [b":method", b":path", b":status", b"x-custom",
                      b"cookie", b"x", bytes(self.rng.sample(vocab, 20)),
                      b"www-authenticate"]
        self.values = [b"GET", b"/", b"200", b"a", b"hello, world",
                       bytes(self.rng.sample(vocab, 30)), b"",
                       b"application/json"]

    def _rand_headers(self, count):
        out = []
        for _ in range(count):
            name = self.rng.choice(self.names)
            value = self.rng.choice(self.values)
            out.append((name, value))
        return out

    def _build_blocks(self, scenario):
        """Return (frame_file, per-block header lists) using the reference
        Encoder, which exercises indexing, Huffman and table eviction."""
        ref_enc = RefEncoder()
        frame_file = b""
        expected = []
        stream_id = 1
        for headers_list, huffman in scenario:
            block = ref_enc.encode(headers_list, huffman=huffman)
            frame_file += split_into_frames(stream_id, block, self.rng)
            expected.append((stream_id, headers_list))
            stream_id += 2
        return frame_file, expected

    def _check(self, frame_file, expected):
        got = audit(frame_file)
        self.assertEqual(len(got), len(expected))
        for (sid, header_list), record in zip(expected, got):
            g_stream, g_offset, g_fields = record
            self.assertEqual(g_stream, sid)
            want = [[n.hex(), v.hex()] for n, v in header_list]
            self.assertEqual(g_fields, want)

    def test_mixed_huffman_plain_multi_block(self):
        scenario = [
            (self._rand_headers(6), True),
            (self._rand_headers(4), False),
            (self._rand_headers(8), True),
        ]
        frame_file, expected = self._build_blocks(scenario)
        self._check(frame_file, expected)

    def test_cross_stream_with_data_and_rst_between_blocks(self):
        ref_enc = RefEncoder()
        frame_file = b""
        expected = []
        blocks = []
        for sid, hlist in ((1, self._rand_headers(3)),
                           (7, self._rand_headers(2)),
                           (9, self._rand_headers(5))):
            block = ref_enc.encode(hlist, huffman=bool(sid & 1))
            blocks.append((sid, block, hlist))
        frame_file += split_into_frames(blocks[0][0], blocks[0][1],
                                        self.rng)
        frame_file += data_frame(blocks[0][0], b"payload", pad=2)
        frame_file += split_into_frames(blocks[1][0], blocks[1][1],
                                        self.rng)
        frame_file += rst(blocks[0][0], 7)
        frame_file += split_into_frames(blocks[2][0], blocks[2][1],
                                        self.rng)
        got = audit(frame_file)
        self.assertEqual([r[0] for r in got], [1, 7, 9])
        for (_, _, hlist), record in zip(blocks, got):
            self.assertEqual(record[2],
                             [[n.hex(), v.hex()] for n, v in hlist])

    def test_dynamic_table_shrink_and_grow(self):
        # Start with a shrink to capacity 0, then back to 4096, then fields.
        block0 = size_update(0) + size_update(4096)
        hlist = self._rand_headers(10)
        ref_enc = RefEncoder()
        block1 = ref_enc.encode(hlist, huffman=True)
        frame_file = (headers(1, block0)
                      + split_into_frames(3, block1, self.rng))
        got = audit(frame_file)
        self.assertEqual(got[0][2], [])
        self.assertEqual(got[1][2],
                         [[n.hex(), v.hex()] for n, v in hlist])

    def test_capacity_shrink_forces_eviction(self):
        # Block 1 inserts an entry of 20+20+32 = 72 bytes.
        b1 = literal_incremental(b"a" * 20, b"b" * 20, False)
        # Block 2 opens with a size update down to 64: the 72-byte entry
        # is evicted; then a 1+1+32 = 34 byte entry fits.
        b2 = size_update(64) + literal_incremental(b"c", b"d", True)
        frame_file = headers(1, b1) + headers(3, b2)
        got = audit(frame_file)
        self.assertEqual(got[0][2], [["61" * 20, "62" * 20]])
        self.assertEqual(got[1][2], [["63", "64"]])
        # Confirm against the reference decoder on block 2's encoding
        # (the shrink semantics are part of RFC 7541 section 4.3).
        ref_dec = RefDecoder()
        ref_dec.decode(b1, raw=True)
        self.assertEqual(
            [[n.hex(), v.hex()] for n, v in ref_dec.decode(b2, raw=True)],
            [["63", "64"]],
        )

    def test_reference_decoder_direct_fuzz(self):
        """Feed blocks produced by the reference Encoder straight into both
        decoders and compare the decoded field lists block by block."""
        ref_enc = RefEncoder()
        ref_dec = RefDecoder()
        ours = __import__("h2audit.hpack", fromlist=["Decoder"]).Decoder()
        for i in range(40):
            hlist = self._rand_headers(self.rng.randint(1, 12))
            block = ref_enc.encode(hlist, huffman=bool(i % 2))
            ref_out = ref_dec.decode(block, raw=True)
            our_out = ours.decode_block(block, 0)
            self.assertEqual(
                our_out,
                [[n.hex(), v.hex()] for n, v in ref_out],
            )

    def test_high_bytes_and_duplicates(self):
        hlist = [(b"\xff\x00", b"\x80\x81"), (b"x", b"a"),
                 (b"x", b"a"), (b"\x7f", b"")]
        ref_enc = RefEncoder()
        block = ref_enc.encode(hlist, huffman=False)
        got = audit(headers(1, block))
        self.assertEqual(
            got[0][2],
            [[n.hex(), v.hex()] for n, v in hlist],
        )


class SpecExampleTest(unittest.TestCase):

    def test_exact_spec_example(self):
        f1 = headers(1, bytes.fromhex("4001780161"))
        f2 = headers(3, bytes.fromhex("be"))
        self.assertEqual(
            audit(f1 + f2),
            [[1, 0, [["78", "61"]]], [3, len(f1), [["78", "61"]]]],
        )

    def test_empty_file_and_empty_block(self):
        self.assertEqual(audit(b""), [])
        self.assertEqual(audit(headers(1, b"")), [[1, 0, []]])


class IndependentRejectionFixtureTests(unittest.TestCase):
    """Hand-built invalid inputs; offsets asserted independently."""

    def test_framing_error_offset_is_frame_start(self):
        good = headers(1, b"\x82")
        bad_type = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"  # SETTINGS-ish
        with self.assertRaises(FramingError) as ctx:
            audit(good + bad_type)
        self.assertEqual(ctx.exception.offset, len(good))

    def test_truncation_reports_frame_start(self):
        good = headers(1, b"\x82")
        with self.assertRaises(FramingError) as ctx:
            audit(good + b"\x00\x00\x05\x00\x00\x00\x00\x00\x01\xab")
        self.assertEqual(ctx.exception.offset, len(good))

    def test_missing_continuation_eof_reports_headers_start(self):
        h0 = headers(1, b"ab", flags=0)           # open block at 0
        h1 = headers(3, b"\x82", flags=0)         # wrong frame mid-block
        with self.assertRaises(FramingError) as ctx:
            audit(h0 + h1)
        self.assertEqual(ctx.exception.offset, len(h0))
        # And EOF with no further frame: report the HEADERS start.
        with self.assertRaises(FramingError) as ctx:
            audit(h0)
        self.assertEqual(ctx.exception.offset, 0)

    def test_hpack_error_offset_is_block_start(self):
        # Valid frame at 0; second block at its offset contains index 62
        # with an empty dynamic table -> HPACK error at that block start.
        f1 = headers(1, b"\x82")
        f2 = headers(3, b"\xbe")
        with self.assertRaises(HpackError) as ctx:
            audit(f1 + f2)
        self.assertEqual(ctx.exception.offset, len(f1))

    def test_invalid_index_zero_rejected_with_block_offset(self):
        with self.assertRaises(HpackError) as ctx:
            audit(headers(5, b"\x80"))
        self.assertEqual(ctx.exception.offset, 0)

    def test_huffman_eos_rejected(self):
        eos = bytes([0xFF] * 3 + [0xC0])
        block = bytes([0x80 | len(eos)]) + eos
        with self.assertRaises(HpackError):
            audit(headers(1, block))

    def test_bad_huffman_padding_rejected(self):
        with self.assertRaises(HpackError):
            audit(headers(1, b"\x81\x00"))

    def test_size_update_after_field_rejected(self):
        with self.assertRaises(HpackError):
            audit(headers(1, b"\x82\x20"))

    def test_all_or_nothing_on_failure(self):
        # First block legal, second block invalid (index 0): no partial
        # result is returned anywhere - audit() raises instead.
        f1 = headers(1, bytes.fromhex("4001780161"))
        f2 = headers(3, b"\x80")
        with self.assertRaises(HpackError):
            audit(f1 + f2)

    def test_end_stream_flag_does_not_close_block(self):
        h = headers(1, b"\x82", flags=END_STREAM)
        with self.assertRaises(FramingError) as ctx:
            audit(h)  # EOF, block still open -> HEADERS start
        self.assertEqual(ctx.exception.offset, 0)


if __name__ == "__main__":
    unittest.main()
