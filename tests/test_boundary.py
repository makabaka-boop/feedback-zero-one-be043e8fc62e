"""Additional regression tests for hard boundaries and long-running
dynamic-table state, cross-checked with the reference hpack library."""

import os
import random
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))

from frame_builder import headers, continuation, CONTINUATION, END_HEADERS  # noqa: E402
from h2audit import audit  # noqa: E402
from h2audit.framing import FramingError  # noqa: E402

sys.path.insert(0, "/home/node/.local/lib/python3.11/site-packages")
try:
    from hpack.hpack import Encoder as RefEncoder, Decoder as RefDecoder
    HAVE_HPACK = True
except ImportError:  # pragma: no cover
    HAVE_HPACK = False


@unittest.skipUnless(HAVE_HPACK, "reference hpack library not installed")
class BoundaryAndStateTests(unittest.TestCase):

    def test_block_split_with_exactly_16384_continuation(self):
        enc = RefEncoder()
        block = enc.encode([("x-big", "z" * 20000)], huffman=False)
        self.assertGreater(len(block), 16384)
        blob = (
            headers(1, block[:100], flags=0)
            + continuation(1, block[100:100 + 16384], flags=0)
            + continuation(1, block[100 + 16384:], flags=END_HEADERS)
        )
        got = audit(blob)
        ref = RefDecoder()
        want = [[n.hex(), v.hex()]
                for n, v in ref.decode(block, raw=True)]
        self.assertEqual(got[0][2], want)

    def test_length_16385_rejected_on_continuation(self):
        h = headers(1, b"\x82", flags=0)
        bad = ((16385).to_bytes(3, "big")
               + bytes((CONTINUATION, 0))
               + (1).to_bytes(4, "big"))
        with self.assertRaises(FramingError) as ctx:
            audit(h + bad)
        self.assertEqual(ctx.exception.offset, len(h))

    def test_sixty_blocks_random_splits_shared_state(self):
        rng = random.Random(424242)
        enc = RefEncoder()
        vocab = [b"a", b"bb", b"custom-name", b":status", b"cookie",
                 bytes(rng.randrange(1, 256)
                       for _ in range(rng.randrange(1, 40)))]
        blob = b""
        expected = []
        for i in range(60):
            hl = [(rng.choice(vocab), rng.choice(vocab))
                  for _ in range(rng.randrange(1, 10))]
            blk = enc.encode(hl, huffman=bool(i % 3))
            sid = 100 + i
            if rng.random() < 0.4 or len(blk) == 1:
                blob += headers(sid, blk)
            else:
                cut = rng.randrange(1, len(blk))
                part = headers(sid, blk[:cut], flags=0)
                rest = blk[cut:]
                while rest:
                    cut2 = rng.randrange(1, len(rest) + 1)
                    frag, rest = rest[:cut2], rest[cut2:]
                    part += continuation(
                        sid, frag, flags=0 if rest else END_HEADERS)
                blob += part
            expected.append((sid, hl))
        got = audit(blob)
        self.assertEqual(len(got), len(expected))
        for (sid, hl), rec in zip(expected, got):
            self.assertEqual(rec[0], sid)
            self.assertEqual(rec[2],
                             [[n.hex(), v.hex()] for n, v in hl])

    def test_dynamic_eviction_matches_reference_sequence(self):
        """Force many insertions so both tables evict; compare every block."""
        enc = RefEncoder()
        ref = RefDecoder()
        from h2audit.hpack import Decoder as OurDecoder
        ours = OurDecoder()
        for i in range(30):
            name = f"name-{i % 7}".encode()
            value = bytes([65 + (i % 26)]) * (50 + i * 10)
            blk = enc.encode([(name, value)], huffman=False)
            ref_fields = ref.decode(blk, raw=True)
            our_fields = ours.decode_block(blk, 0)
            self.assertEqual(
                our_fields,
                [[n.hex(), v.hex()] for n, v in ref_fields],
            )
            # Dynamic-table bookkeeping must match the reference exactly.
            self.assertEqual(ours._dynamic.size,
                             ref.header_table._current_size)
            self.assertEqual(len(ours._dynamic),
                             len(ref.header_table.dynamic_entries))
            # Sizes must never exceed the 4096 ceiling.
            self.assertLessEqual(ours._dynamic.size, 4096)


if __name__ == "__main__":
    unittest.main()
