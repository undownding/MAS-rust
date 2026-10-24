#!/usr/bin/env python3
"""Synthetic tokens.dat and TokenMeta vectors from pinned LibTSforge layout."""
from pathlib import Path
import hashlib
import struct

ROOT = Path(__file__).resolve().parents[1] / 'tests/fixtures/tsforge'
BLOCK, ENTRY, SLOTS = 0x4020, 0x9E, 103


def words(*args):
    return struct.pack('<' + 'I' * len(args), *args)


def text(value):
    return (value + '\0').encode('utf-16-le')


def field(value, size):
    data = text(value)
    assert len(data) <= size
    return data.ljust(size, b'\0')


def main():
    ROOT.mkdir(parents=True, exist_ok=True)
    metadata = words(1, len(text('测试😀'))) + text('测试😀')
    for key, value in [('重复', 'first'), ('重复', 'second'), ('', '')]:
        key, value = text(key), text(value)
        metadata += words(len(key), len(value)) + key + value
    (ROOT / 'token-meta.bin').write_bytes(metadata)
    output = bytearray(words(3) + bytes(32))
    for block in range(2):
        offset = len(output)
        output.extend(bytes(BLOCK))
        struct.pack_into('<I', output, offset, offset)
        for slot in range(SLOTS):
            current = offset + 8 + slot * ENTRY
            name, extension, data = '', '', None
            if block == 0 and slot == 0:
                name, extension, data = '测试😀', 'xml', metadata
            if block == 0 and slot == 1:
                name, extension = 'inactive', 'xml'
            if block == 1 and slot == 0:
                name, extension, data = 'empty-data', 'bin', b''
            if data is None:
                record = words(current, 0, 0, 0xFFFFFFFF, 0xFFFFFFFF)
            else:
                record = words(current, 1, len(output), len(data), len(data))
                output.extend(bytes([0x55]) * 32 + words(len(data)) + hashlib.sha256(data).digest() + data + bytes([0xAA]) * 32)
            record += field(name, 0x82) + field(extension, 8)
            assert len(record) == ENTRY
            output[current:current + ENTRY] = record
        if block == 0:
            struct.pack_into('<I', output, offset + 4, len(output))
        output[offset + BLOCK - 32:offset + BLOCK] = hashlib.sha256(output[offset:offset + BLOCK - 32]).digest()
    output[4:36] = hashlib.sha256(output[:4] + output[36:]).digest()
    (ROOT / 'tokens-modern.bin').write_bytes(output)


if __name__ == '__main__':
    main()
