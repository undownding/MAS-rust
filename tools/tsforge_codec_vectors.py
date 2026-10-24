#!/usr/bin/env python3
"""Synthetic vectors from pinned MAS format definitions, independent of Rust codecs.

CRC uses a polynomial-division implementation rather than the Rust bit loop.
No machine licensing data is included. Run from any working directory.
"""
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1] / 'tests/fixtures/tsforge'


def words(*values):
    return struct.pack('<' + 'I' * len(values), *values)


def crc(data):
    polynomial = 0x104C11DB7
    dividend = (int.from_bytes(data, 'big') << 32) ^ (0xFFFFFFFF << (8 * len(data)))
    while dividend.bit_length() > 32:
        dividend ^= polynomial << (dividend.bit_length() - 33)
    return dividend ^ 0xFFFFFFFF


def pad(data, alignment):
    data.extend(bytes(-len(data) % alignment))


def main():
    assert crc(b'123456789') == 0xFC891918
    ROOT.mkdir(parents=True, exist_ok=True)
    entries = [(0xDEADBEEF, b'K\0\0\0', b'123456789'), (2, b'K\0\0\0', b'\xff'), (0, b'', b'')]
    for modern in (False, True):
        output = bytearray()
        for kind, key, value in entries:
            if modern:
                checksum = crc(words(0, kind, len(key), len(value)) + key + value)
                output.extend(words(checksum, kind, len(key), len(value)))
                output.extend(key)
                pad(output, 8)
                output.extend(value)
                pad(output, 8)
            else:
                output.extend(words(kind, 0x76543210, len(key), len(value), crc(value)) + key + value)
        (ROOT / ('bag-modern.bin' if modern else 'bag-vista.bin')).write_bytes(output)

    for version in ('vista', 'win7', 'modern'):
        output = bytearray(b'PREHEAD!')
        name = b'K\0\0\0'
        if version == 'modern':
            output.extend(words(2, len(name)) + name + words(1))
            pad(output, 4)
        for i in range(2):
            if i and version == 'modern':
                output.extend(words(len(name)) + name + words(1))
                pad(output, 4)
            value, data = b'v\0\0\0', b'abc'
            output.extend(words(0xDEADBEEF, 0x87654321))
            if version == 'win7':
                output.extend(words(len(name)))
            output.extend(words(len(value), len(data)))
            if version == 'modern':
                output.extend(words(0xAABBCCDD))
            if version == 'win7':
                output.extend(name)
            output.extend(value + data)
            pad(output, 4)
        if version == 'modern':
            output.extend(words(0))
        (ROOT / f'store-{version}.bin').write_bytes(output)


if __name__ == '__main__':
    main()
