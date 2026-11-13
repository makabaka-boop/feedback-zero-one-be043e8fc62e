"""Framing layer tests (RFC 9113 sections 4 and 6)."""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from frame_builder import (  # noqa: E402
    frame, headers, continuation, data_frame, rst,
    END_STREAM, END_HEADERS, PADDED, PRIORITY,
    HEADERS, CONTINUATION, DATA, RST_STREAM,
)
from h2audit.framing import split_header_blocks, FramingError  # noqa: E402


def blocks(data):
    return [(b.stream_id, b.offset, b.payload) for b in
            split_header_blocks(data)]


class FramingHappyPathTests(unittest.TestCase):

    def test_single_headers_block(self):
        data = headers(1, b"\xbe")
        self.assertEqual(blocks(data), [(1, 0, b"\xbe")])

    def test_headers_with_end_stream_does_not_end_block(self):
        # END_STREAM but no END_HEADERS: a CONTINUATION is still required.
        h = headers(1, b"\x82", flags=END_STREAM)
        c = continuation(1, b"\x84")
        self.assertEqual(blocks(h + c), [(1, 0, b"\x82\x84")])

    def test_block_spanning_multiple_continuations(self):
        h = headers(3, b"aa", flags=0)
        c1 = continuation(3, b"bb", flags=0)
        c2 = continuation(3, b"cc")
        self.assertEqual(blocks(h + c1 + c2),
                         [(3, 0, b"aabbcc")])

    def test_two_streams_interleaved_with_data_and_rst(self):
        h1 = headers(1, b"\x82", flags=0)
        # DATA/RST may NOT appear mid-block; put them between closed blocks.
        c1 = continuation(1, b"\x84")
        d = data_frame(1, b"hello")
        r = rst(1, 8)
        h2 = headers(5, b"\x83")
        h2_offset = len(h1) + len(c1) + len(d) + len(r)
        out = blocks(h1 + c1 + d + r + h2)
        self.assertEqual(out, [(1, 0, b"\x82\x84"),
                               (5, h2_offset, b"\x83")])

    def test_padded_and_priority_headers_stripped(self):
        priority = b"\x00\x00\x00\x00\x0f"  # E=0, dep=0, weight=15
        h = headers(1, b"\xbe", pad=3, priority=priority)
        # pad-length byte and 5 priority bytes and 3 padding bytes removed
        self.assertEqual(blocks(h), [(1, 0, b"\xbe")])

    def test_padded_data_validated_then_ignored(self):
        d = data_frame(1, b"x", pad=2)
        self.assertEqual(blocks(d), [])

    def test_rst_exact_four_bytes_ignored(self):
        self.assertEqual(blocks(rst(9, 7)), [])

    def test_unknown_flags_and_reserved_bits_ignored(self):
        # 0x40 is an unknown HEADERS flag; R bit set in stream id.
        h = frame(HEADERS, END_HEADERS | 0x40, 1, b"\x82", reserved=1)
        self.assertEqual(blocks(h), [(1, 0, b"\x82")])

    def test_empty_file(self):
        self.assertEqual(split_header_blocks(b""), [])

    def test_empty_block(self):
        self.assertEqual(blocks(headers(1, b"")), [(1, 0, b"")])

    def test_offset_skips_previous_frames(self):
        d = data_frame(1, b"0123456789")  # 19 bytes
        h = headers(3, b"\xbe")
        self.assertEqual(blocks(d + h), [(3, 19, b"\xbe")])

    def test_maximum_length_frame_accepted(self):
        fragment = b"\x00" * 16384
        h = headers(1, fragment)
        self.assertEqual(blocks(h), [(1, 0, fragment)])


class FramingRejectionTests(unittest.TestCase):

    def _expect(self, data, offset):
        with self.assertRaises(FramingError) as ctx:
            split_header_blocks(data)
        self.assertEqual(ctx.exception.offset, offset,
                         msg=str(ctx.exception))

    def test_truncated_frame_header(self):
        self._expect(frame(HEADERS, END_HEADERS, 1, b"x")[:5], 0)

    def test_truncated_payload_reports_frame_start(self):
        good = headers(1, b"\xbe")
        self._expect(good + frame(DATA, 0, 1, b"1234")[:-2], len(good))

    def test_length_over_16384_rejected(self):
        big = (16385).to_bytes(3, "big") + bytes((HEADERS, END_HEADERS)) \
            + (1).to_bytes(4, "big") + b"\x00"
        self._expect(big, 0)

    def test_unknown_frame_type_rejected(self):
        # 0x4 (SETTINGS) must have been removed by the caller.
        self._expect(frame(0x4, 0, 0, b""), 0)

    def test_continuation_without_headers(self):
        self._expect(continuation(1, b"x"), 0)

    def test_continuation_wrong_stream(self):
        h = headers(1, b"a", flags=0)
        c = continuation(2, b"b")
        self._expect(h + c, len(h))

    def test_non_continuation_mid_block_reports_that_frame(self):
        h = headers(1, b"a", flags=0)
        d = data_frame(1, b"x")
        self._expect(h + d, len(h))

    def test_end_stream_mid_block_still_needs_continuation(self):
        h = headers(1, b"a", flags=END_STREAM)  # no END_HEADERS
        self._expect(h + data_frame(1, b"x"), len(h))

    def test_eof_waiting_continuation_reports_headers_start(self):
        h0 = headers(1, b"a", flags=0)
        offset = len(h0)
        h1 = headers(3, b"b", flags=0)
        with self.assertRaises(FramingError) as ctx:
            split_header_blocks(h0 + h1)
        self.assertEqual(ctx.exception.offset, offset)

    def test_eof_single_open_block_reports_zero(self):
        h = headers(1, b"a", flags=0)
        with self.assertRaises(FramingError) as ctx:
            split_header_blocks(h)
        self.assertEqual(ctx.exception.offset, 0)

    def test_headers_on_stream_zero(self):
        self._expect(frame(HEADERS, END_HEADERS, 0, b"\x82"), 0)

    def test_data_on_stream_zero(self):
        self._expect(frame(DATA, 0, 0, b"x"), 0)

    def test_rst_on_stream_zero(self):
        self._expect(frame(RST_STREAM, 0, 0, b"\x00" * 4), 0)

    def test_rst_bad_length(self):
        self._expect(frame(RST_STREAM, 0, 1, b"\x00" * 3), 0)
        self._expect(frame(RST_STREAM, 0, 1, b"\x00" * 5), 0)

    def test_padded_headers_missing_pad_length(self):
        payload = b""  # PADDED set but no bytes
        self._expect(frame(HEADERS, PADDED | END_HEADERS, 1, payload), 0)

    def test_padded_headers_pad_too_long(self):
        payload = bytes((5,)) + b"ab"  # pad length 5 > 2 remaining
        self._expect(frame(HEADERS, PADDED | END_HEADERS, 1, payload), 0)

    def test_priority_headers_missing_five_bytes(self):
        payload = b"\x00\x00"  # PRIORITY set, only 2 bytes
        self._expect(
            frame(HEADERS, PRIORITY | END_HEADERS, 1, payload), 0)

    def test_padded_data_pad_too_long(self):
        payload = bytes((4,)) + b"ab"
        self._expect(frame(DATA, PADDED, 1, payload), 0)

    def test_padded_data_missing_pad_length(self):
        self._expect(frame(DATA, PADDED, 1, b""), 0)

    def test_continuation_also_capped(self):
        over = (16385).to_bytes(3, "big") + bytes((CONTINUATION, 0)) \
            + (1).to_bytes(4, "big")
        self._expect(over, 0)

    def test_padded_empty_fragment(self):
        # pad length consumes the whole payload: legal empty block.
        payload = bytes([1, 0xAA])
        out = split_header_blocks(
            frame(HEADERS, PADDED | END_HEADERS, 1, payload))
        self.assertEqual(out[0].payload, b"")

    def test_padded_priority_empty_fragment(self):
        payload = bytes([0]) + b"\x00\x00\x00\x00\x05"
        out = split_header_blocks(
            frame(HEADERS, PADDED | PRIORITY | END_HEADERS, 1, payload))
        self.assertEqual(out[0].payload, b"")

    def test_priority_bytes_eaten_by_padding_rejected(self):
        payload = bytes([5, 1, 2, 3, 4, 5])  # padding leaves 0 for priority
        self._expect(
            frame(HEADERS, PADDED | PRIORITY | END_HEADERS, 1, payload), 0)

    def test_first_error_reported_not_later_one(self):
        bad = frame(0x4, 0, 0, b"")           # unknown type at 0
        good = headers(1, b"\xbe")
        self._expect(bad + good, 0)


if __name__ == "__main__":
    unittest.main()
