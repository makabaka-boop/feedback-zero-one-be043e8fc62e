"""HPACK decoder unit tests (RFC 7541)."""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from h2audit.hpack import (  # noqa: E402
    decode_integer, decode_string, decode_huffman, Decoder, DynamicTable,
    HpackError, MAX_TABLE_CAPACITY, ENTRY_OVERHEAD,
)
from h2audit.tables import STATIC_TABLE  # noqa: E402

OFF = 0  # block-start offset used in these unit tests


def encode_integer(value: int, prefix_bits: int) -> bytes:
    """Minimal RFC 7541 section 5.1 encoder used to build fixtures."""
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


def literal(name: bytes, value: bytes) -> bytes:
    """Literal with incremental indexing, new name (index 0)."""
    return b"\x40" + encode_integer(len(name), 7) + name \
        + encode_integer(len(value), 7) + value


class IntegerTests(unittest.TestCase):

    def decode(self, data, prefix_bits):
        value, pos = decode_integer(bytes(data), 0, prefix_bits, OFF)
        return value, pos

    def test_rfc_512_examples(self):
        # section 5.1.2, 5-bit prefix
        self.assertEqual(self.decode([0b00001010], 5), (10, 1))
        # 1337 = 31 + (26 + 10*128): continuation bytes 0x9a, 0x0a
        self.assertEqual(
            self.decode([0b00011111, 0b10011010, 0b00001010], 5),
            (1337, 3))
        # section 5.1.3, 8-bit prefix
        self.assertEqual(self.decode([42], 8), (42, 1))
        self.assertEqual(self.decode([255, 0], 8), (255, 2))
        self.assertEqual(self.decode([255, 1], 8), (256, 2))

    def test_no_artificial_value_cap(self):
        # A finite multi-byte encoding of a large value must be accepted
        # exactly by its mathematical value (no domain/byte-count ceiling).
        encoded = [0x1F] + [0x80] * 20 + [0x01]
        value, pos = self.decode(encoded, 5)
        self.assertEqual(value, 31 + (1 << (7 * 20)))
        self.assertEqual(pos, len(encoded))

    def test_truncated_forms_rejected(self):
        with self.assertRaises(HpackError):
            decode_integer(b"", 0, 5, OFF)
        with self.assertRaises(HpackError):
            decode_integer(b"\x1f", 0, 5, OFF)
        with self.assertRaises(HpackError):
            decode_integer(b"\x1f\x80", 0, 5, OFF)


class StringTests(unittest.TestCase):

    def test_plain_string(self):
        raw, pos = decode_string(b"\x03abc", 0, OFF)
        self.assertEqual(raw, b"abc")
        self.assertEqual(pos, 4)

    def test_truncated_string(self):
        with self.assertRaises(HpackError):
            decode_string(b"\x05ab", 0, OFF)

    def test_huffman_eos_rejected(self):
        # 30 one-bits encode the EOS symbol (Appendix B, symbol 256).
        eos = bytes([0xFF] * 3 + [0xC0])
        block = bytes([0x80 | len(eos)]) + eos
        with self.assertRaises(HpackError):
            decode_string(block, 0, OFF)

    def test_huffman_bad_padding_rejected(self):
        # Valid code for '0' is 5 bits (00000); pad with a zero bit ->
        # invalid padding because the padding bits must all be ones.
        # byte 0000 0|0 -> code 0 over 5 bits leaves 1 zero padding bit.
        block = b"\x81\x00"
        with self.assertRaises(HpackError):
            decode_string(block, 0, OFF)

    def test_huffman_valid_padding_accepted(self):
        # '0' code 00000 padded with three one bits -> 0000 0111 = 0x07
        raw, pos = decode_string(b"\x81\x07", 0, OFF)
        self.assertEqual(raw, b"0")
        self.assertEqual(pos, 2)

    def test_huffman_undecodable_prefix_rejected(self):
        # 0x1e = 00011110: after the 6-bit code of '0' (000000) the
        # remaining 1110 cannot begin any Huffman code and has non-ones
        # padding, so it must be rejected (never silently output).
        with self.assertRaises(HpackError):
            decode_string(b"\x81\x1e", 0, OFF)

    def test_empty_string(self):
        raw, pos = decode_string(b"\x00", 0, OFF)
        self.assertEqual(raw, b"")
        self.assertEqual(pos, 1)
        raw, pos = decode_string(b"\x80", 0, OFF)
        self.assertEqual(raw, b"")


class DynamicTableTests(unittest.TestCase):

    def test_entry_size_is_decoded_bytes_plus_32(self):
        table = DynamicTable()
        table.add(b"name", b"value")
        self.assertEqual(table.size, 4 + 5 + ENTRY_OVERHEAD)

    def test_newest_first_order(self):
        table = DynamicTable()
        table.add(b"a", b"1")
        table.add(b"b", b"2")
        self.assertEqual(table.get(1), (b"b", b"2"))
        self.assertEqual(table.get(2), (b"a", b"1"))

    def test_eviction_oldest_first(self):
        table = DynamicTable(capacity=64)
        # each entry costs 3+3+32 = 38; only one fits.
        table.add(b"aaa", b"bbb")
        table.add(b"ccc", b"ddd")
        self.assertEqual(len(table), 1)
        self.assertEqual(table.get(1), (b"ccc", b"ddd"))

    def test_oversized_entry_clears_table_but_field_is_emitted(self):
        dec = Decoder()
        dec._dynamic.add(b"keep", b"me")  # 4+2+32 = 38
        big_name = b"n" * 100
        big_value = b"v" * 100
        block = literal(big_name, big_value)  # size 232 > capacity 4096? no
        # 100+100+32 = 232 fits, so make it genuinely oversized instead:
        big_value = b"v" * 5000              # name+value+32 = 5132 > 4096
        block = literal(big_name, big_value)
        fields = dec.decode_block(block, OFF)
        self.assertEqual(fields,
                         [[big_name.hex(), big_value.hex()]])
        # The table was cleared and the oversized entry was not inserted.
        self.assertEqual(len(dec._dynamic), 0)
        self.assertEqual(dec._dynamic.size, 0)

    def test_name_taken_before_eviction(self):
        dec = Decoder()
        # Insert (x, a); then a literal referencing dynamic index 62 with a
        # huge value: the name b"x" must be resolved before eviction.
        dec.decode_block(bytes.fromhex("4001780161"), OFF)
        big = b"v" * 5000
        # incremental literal, named index 62, then value string
        block = b"\x7e" + encode_integer(len(big), 7) + big
        fields = dec.decode_block(block, OFF)
        self.assertEqual(fields, [["78", big.hex()]])
        self.assertEqual(len(dec._dynamic), 0)

    def test_resize_shrinks_and_grows_within_ceiling(self):
        table = DynamicTable()
        table.add(b"a", b"1")  # 35
        table.resize(10)
        self.assertEqual(table.capacity, 10)
        self.assertEqual(len(table), 0)
        table.resize(100)
        self.assertEqual(table.capacity, 100)
        table.add(b"b", b"2")
        self.assertEqual(table.size, 1 + 1 + ENTRY_OVERHEAD)  # 34


class BlockDecodingTests(unittest.TestCase):

    def test_indexed_static(self):
        dec = Decoder()
        # index 2 -> (:method, GET); index 61 -> (www-authenticate, "")
        self.assertEqual(dec.decode_block(b"\x82", OFF),
                         [["3a6d6574686f64", "474554"]])
        self.assertEqual(dec.decode_block(bytes([0x80 | 61]), OFF),
                         [["7777772d61757468656e746963617465", ""]])

    def test_index_zero_rejected(self):
        with self.assertRaises(HpackError):
            Decoder().decode_block(b"\x80", OFF)

    def test_index_beyond_tables_rejected(self):
        with self.assertRaises(HpackError):
            Decoder().decode_block(b"\xbe", OFF)  # 62, empty dynamic table

    def test_literal_incremental_indexes(self):
        dec = Decoder()
        out = dec.decode_block(bytes.fromhex("4001780161"), OFF)
        self.assertEqual(out, [["78", "61"]])
        # now dynamic absolute index 62 must resolve to that entry
        out = dec.decode_block(b"\xbe", OFF)
        self.assertEqual(out, [["78", "61"]])

    def test_literal_without_indexing(self):
        dec = Decoder()
        # 0000 | 0000 (index 0), name "x", value "a"
        block = b"\x00\x01x\x01a"
        self.assertEqual(dec.decode_block(block, OFF), [["78", "61"]])
        self.assertEqual(len(dec._dynamic), 0)

    def test_never_indexed(self):
        dec = Decoder()
        block = b"\x10\x01x\x01a"
        self.assertEqual(dec.decode_block(block, OFF), [["78", "61"]])
        self.assertEqual(len(dec._dynamic), 0)

    def test_literal_with_named_index(self):
        dec = Decoder()
        # incremental, name index 1 (:authority), value "example.com"
        block = b"\x41\x0bexample.com"
        out = dec.decode_block(block, OFF)
        self.assertEqual(out, [["3a617574686f72697479",
                                "6578616d706c652e636f6d"]])
        self.assertEqual(dec._dynamic.get(1),
                         (b":authority", b"example.com"))

    def test_empty_block(self):
        self.assertEqual(Decoder().decode_block(b"", OFF), [])

    def test_size_update_only_at_start(self):
        dec = Decoder()
        # field first, then size update -> reject
        block = b"\x82\x3e"
        with self.assertRaises(HpackError):
            dec.decode_block(block, OFF)

    def test_size_update_above_ceiling_rejected(self):
        # 4097 over a 5-bit prefix: 0x1f 0xe2 0x1f
        with self.assertRaises(HpackError):
            Decoder().decode_block(b"\x3f\xe2\x1f", OFF)  # 4097

    def test_size_update_4096_accepted(self):
        dec = Decoder()
        dec.decode_block(b"\x3f\xe1\x1f", OFF)  # 4096
        self.assertEqual(dec._dynamic.capacity, MAX_TABLE_CAPACITY)

    def test_size_update_zero_evicts(self):
        dec = Decoder()
        dec.decode_block(bytes.fromhex("4001780161"), OFF)
        self.assertEqual(len(dec._dynamic), 1)
        dec.decode_block(b"\x20", OFF)  # new size 0
        self.assertEqual(len(dec._dynamic), 0)
        self.assertEqual(dec._dynamic.capacity, 0)

    def test_dynamic_state_persists_across_blocks(self):
        dec = Decoder()
        dec.decode_block(bytes.fromhex("4001780161"), OFF)
        # a different block still sees the entry
        self.assertEqual(dec.decode_block(b"\xbe", 99), [["78", "61"]])

    def test_error_offset_is_block_start(self):
        dec = Decoder()
        with self.assertRaises(HpackError) as ctx:
            dec.decode_block(b"\x80", 1234)
        self.assertEqual(ctx.exception.offset, 1234)

    def test_duplicate_fields_preserved_in_order(self):
        dec = Decoder()
        block = bytes.fromhex("4001780161") + bytes.fromhex("4001780161")
        out = dec.decode_block(block, OFF)
        self.assertEqual(out, [["78", "61"], ["78", "61"]])

    def test_high_bytes_preserved_as_hex(self):
        dec = Decoder()
        name = b"\xff\xfe"
        value = b"\x00\x01\x80"
        block = b"\x40" + bytes([len(name)]) + name \
            + bytes([len(value)]) + value
        out = dec.decode_block(block, OFF)
        self.assertEqual(out, [["fffe", "000180"]])


if __name__ == "__main__":
    unittest.main()
