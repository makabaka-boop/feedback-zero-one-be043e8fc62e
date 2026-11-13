"""Self-contained HPACK decoder (RFC 7541), including Huffman decoding.

No third-party protocol decoder is used at runtime; the standard code
tables live in :mod:`h2audit.tables`.

Design points required by the task:

* integers are decoded by the exact mathematical procedure of RFC 7541
  section 5.1, with no extra value-domain or byte-count ceiling for finite
  encodings;
* the dynamic table starts empty with both size and capacity 4096, and
  table-size updates are only legal at the very beginning of a block;
* an entry's size is the decoded byte length plus 32; an entry larger than
  the capacity evicts the whole table but is still emitted, and the name
  is always resolved before eviction;
* invalid indexes, the Huffman EOS symbol and invalid Huffman padding are
  rejected;
* the decoder carries dynamic-table state across the blocks of one file.
"""

from .tables import STATIC_TABLE, HUFFMAN_TABLE

# Hard protocol ceiling used in this auditor (SETTINGS_HEADER_TABLE_SIZE
# is negotiated elsewhere); the table may shrink below this but never
# grow beyond it.
MAX_TABLE_CAPACITY = 4096
ENTRY_OVERHEAD = 32
HUFFMAN_EOS = 256
HUFFMAN_MAX_BITS = 30

# Indexed:        1xxxxxxx
# Incremental:    01xxxxxx
# Size update:    001xxxxx
# Never indexed:  0001xxxx
# Without index:  0000xxxx
_BIT_INDEXED = 0x80
_BIT_INCREMENTAL = 0x40
_BIT_SIZE_UPDATE = 0x20
_BIT_NEVER_INDEXED = 0x10


class HpackError(Exception):
    """An HPACK violation.

    ``offset`` is always the start of the header block whose decoding
    failed (the offset of its HEADERS frame).
    """

    def __init__(self, message: str, offset: int):
        super().__init__(f"{message} in block starting at byte {offset}")
        self.offset = offset


# (code, bit_length) -> symbol, for exact-match decoding.
_HUFFMAN_BY_CODE = {
    (code, bit_length): symbol
    for symbol, (code, bit_length) in enumerate(HUFFMAN_TABLE)
}


def decode_huffman(data: bytes, block_offset: int) -> bytes:
    """Decode a Huffman-encoded string literal per RFC 7541 section 5.2."""
    out = bytearray()
    accumulator = 0
    nbits = 0
    for byte in data:
        for shift in range(7, -1, -1):
            accumulator = (accumulator << 1) | ((byte >> shift) & 1)
            nbits += 1
            symbol = _HUFFMAN_BY_CODE.get((accumulator, nbits))
            if symbol is not None:
                if symbol == HUFFMAN_EOS:
                    raise HpackError(
                        "Huffman end-of-string symbol must not appear in a "
                        "string literal",
                        block_offset,
                    )
                out.append(symbol)
                accumulator = 0
                nbits = 0
            elif nbits > HUFFMAN_MAX_BITS:
                raise HpackError(
                    "Huffman sequence matches no code", block_offset
                )
    if nbits:
        # Trailing padding: strictly shorter than the longest code and, per
        # section 5.2, made entirely of one bits (the EOS prefix).
        if nbits >= HUFFMAN_MAX_BITS:
            raise HpackError(
                "Huffman padding is as long as the longest code",
                block_offset,
            )
        if accumulator != (1 << nbits) - 1:
            raise HpackError(
                "Huffman padding bits must all be ones", block_offset
            )
    return bytes(out)


def decode_integer(data: bytes, pos: int, prefix_bits: int,
                   block_offset: int):
    """Decode an integer per RFC 7541 section 5.1.

    Returns ``(value, new_pos)``.  Only structural truncation is rejected;
    no upper bound is imposed on the resulting mathematical value.
    """
    if pos >= len(data):
        raise HpackError("truncated integer encoding", block_offset)
    prefix_mask = (1 << prefix_bits) - 1
    value = data[pos] & prefix_mask
    pos += 1
    if value < prefix_mask:
        return value, pos
    shift = 0
    while True:
        if pos >= len(data):
            raise HpackError(
                "truncated multi-byte integer encoding", block_offset
            )
        byte = data[pos]
        pos += 1
        value += (byte & 0x7F) << shift
        shift += 7
        if not (byte & 0x80):
            break
    return value, pos


def decode_string(data: bytes, pos: int, block_offset: int):
    """Decode a string literal (section 5.2), returning ``(bytes, pos)``."""
    if pos >= len(data):
        raise HpackError("truncated string literal", block_offset)
    huffman_flag = (data[pos] & 0x80) >> 7
    length, pos = decode_integer(data, pos, 7, block_offset)
    end = pos + length
    if end > len(data):
        raise HpackError(
            f"string literal of {length} bytes exceeds the block",
            block_offset,
        )
    raw = data[pos:end]
    if huffman_flag:
        return decode_huffman(raw, block_offset), end
    return bytes(raw), end


class DynamicTable:
    """Newest-first dynamic table (RFC 7541 section 2.3.2)."""

    def __init__(self, capacity: int = MAX_TABLE_CAPACITY):
        self._capacity = capacity
        self._size = 0
        self._entries = []  # index 1 here is the newest entry

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def size(self) -> int:
        return self._size

    def __len__(self) -> int:
        return len(self._entries)

    def get(self, dynamic_index: int):
        if not 1 <= dynamic_index <= len(self._entries):
            raise IndexError(dynamic_index)
        return self._entries[dynamic_index - 1]

    def resize(self, new_capacity: int):
        """Shrink (or grow within the ceiling) and evict as required."""
        self._capacity = new_capacity
        self._evict_to_fit()

    def add(self, name: bytes, value: bytes):
        """Insert an entry, evicting oldest entries first (section 4.4)."""
        entry_size = len(name) + len(value) + ENTRY_OVERHEAD
        while self._entries and self._size + entry_size > self._capacity:
            evicted = self._entries.pop()
            self._size -= len(evicted[0]) + len(evicted[1]) + ENTRY_OVERHEAD
        if entry_size <= self._capacity:
            self._entries.insert(0, (name, value))
            self._size += entry_size
        # An entry larger than the capacity leaves the table empty and is
        # simply not inserted; the field itself is still emitted.

    def _evict_to_fit(self):
        while self._entries and self._size > self._capacity:
            evicted = self._entries.pop()
            self._size -= len(evicted[0]) + len(evicted[1]) + ENTRY_OVERHEAD


class Decoder:
    """Stateful HPACK decoder shared by all blocks of one input file."""

    def __init__(self):
        self._dynamic = DynamicTable()

    def _resolve(self, index: int, block_offset: int):
        """Map an absolute index (section 2.3.3) to a (name, value) pair."""
        if index <= 0:
            raise HpackError(
                f"invalid header table index {index}", block_offset
            )
        if index <= len(STATIC_TABLE):
            return STATIC_TABLE[index - 1]
        dynamic_index = index - len(STATIC_TABLE)
        try:
            return self._dynamic.get(dynamic_index)
        except IndexError:
            raise HpackError(
                f"header table index {index} exceeds the dynamic table",
                block_offset,
            )

    def _decode_literal(self, block, pos, prefix_bits, block_offset,
                        indexable):
        name_index, pos = decode_integer(
            block, pos, prefix_bits, block_offset
        )
        if name_index == 0:
            name, pos = decode_string(block, pos, block_offset)
        else:
            # The name is fully resolved before any eviction happens.
            name, _ = self._resolve(name_index, block_offset)
        value, pos = decode_string(block, pos, block_offset)
        if indexable:
            self._dynamic.add(name, value)
        return (name, value), pos

    def decode_block(self, block: bytes, block_offset: int):
        """Decode one complete header block.

        Returns the fields in original order as ``[name_hex, value_hex]``
        pairs (lowercase hexadecimal, byte-preserving).
        """
        pos = 0
        fields = []
        seen_field = False
        while pos < len(block):
            first = block[pos]
            if first & _BIT_INDEXED:
                index, pos = decode_integer(
                    block, pos, 7, block_offset
                )
                name, value = self._resolve(index, block_offset)
                fields.append([name.hex(), value.hex()])
                seen_field = True
            elif first & _BIT_INCREMENTAL:
                pair, pos = self._decode_literal(
                    block, pos, 6, block_offset, indexable=True
                )
                name, value = pair
                fields.append([name.hex(), value.hex()])
                seen_field = True
            elif first & _BIT_SIZE_UPDATE:
                if seen_field:
                    raise HpackError(
                        "dynamic table size update is only allowed at the "
                        "start of a header block",
                        block_offset,
                    )
                new_size, pos = decode_integer(
                    block, pos, 5, block_offset
                )
                if new_size > MAX_TABLE_CAPACITY:
                    raise HpackError(
                        f"dynamic table size {new_size} exceeds the "
                        f"negotiated maximum {MAX_TABLE_CAPACITY}",
                        block_offset,
                    )
                self._dynamic.resize(new_size)
            else:
                # 0000xxxx (without indexing) or 0001xxxx (never indexed):
                # identical decoding, neither touches the dynamic table.
                indexable = False
                pair, pos = self._decode_literal(
                    block, pos, 4, block_offset, indexable
                )
                name, value = pair
                fields.append([name.hex(), value.hex()])
                seen_field = True
        if pos != len(block):
            raise HpackError("trailing bytes after header block",
                             block_offset)
        return fields


# Module-level convenience for callers that only need a single block.
def decode_block(block: bytes, block_offset: int = 0):
    return Decoder().decode_block(block, block_offset)
