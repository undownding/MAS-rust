#!/usr/bin/env python3
"""Synthetic PKEY2009 vectors; uses upstream byte-wise division, not Rust u128 conversion.

No keys are installed. CRC is supplied by the independent polynomial-division
implementation in tsforge_codec_vectors.py. Metadata/date are fixed test inputs.
"""
import hashlib
import json
import struct
import uuid
from tsforge_codec_vectors import ROOT, crc, words

ALPHABET = 'BCDFGHJKMPQRTVWXY2346789'
URI = 'msft:rm/algorithm/pkey/2009'


def utf16(value):
    return (value + '\0').encode('utf-16-le')


def fixed(value, width):
    data = utf16(value)
    assert len(data) <= width
    return data.ljust(width, b'\0')


def bag(entries):
    result = bytearray()
    for kind, name, value in entries:
        name = utf16(name)
        checksum = crc(words(0, kind, len(name), len(value)) + name + value)
        result.extend(words(checksum, kind, len(name), len(value)) + name)
        result.extend(bytes(-len(result) % 8))
        result.extend(value)
        result.extend(bytes(-len(result) % 8))
    return bytes(result)


def vector(group, serial, security, upgrade):
    low = ((security & 0x3fff) << 50) | (serial << 20) | group
    high = (int(upgrade) << 49) | (security >> 14)
    checksum = crc(struct.pack('<QQ', low, high)) & 0x3ff
    high |= checksum << 39
    data = struct.pack('<QQ', low, high)
    quotient = bytearray(data)
    digits = ''
    for _ in range(25):
        remainder = 0
        for index in range(14, -1, -1):
            current = remainder * 256 + quotient[index]
            quotient[index], remainder = divmod(current, 24)
        digits = ALPHABET[remainder] + digits
    digits = digits[1:1 + remainder] + 'N' + digits[1 + remainder:]
    text = '-'.join(digits[i:i + 5] for i in range(0, 25, 5))
    binding = bag([(2, 'SppPkeyBindingProductKey', utf16(text)), (4, 'SppPkeyBindingMiscData', b''), (2, 'SppPkeyBindingAlgorithm', utf16(URI))])
    phone = uuid.UUID('660672ef-7809-4cfd-8d54-41b7fb738988').bytes_le + struct.pack('<IIIIQ', group, serial // 1000000, serial % 1000000, upgrade, security)
    short = ((group << 41) | (security << 31) | (serial << 1) | int(upgrade)) & ((1 << 64) - 1)
    pid3 = words(0xA4, 3) + bytes(24) + words(group) + b'X00-12345'.ljust(16, b'\0') + bytes(0x6C)
    pid3 += struct.pack('>I', (~crc(pid3[::-1])) & 0xFFFFFFFF)
    extended = f'03612-{group:05}-{serial // 1000000:03}-{serial % 1000000:06}-03-2052-26100.0000-2982026'
    pid4 = words(0x4F8, 4) + fixed(extended, 128) + fixed('55c92734-d682-4d71-983e-d6ec3f16059f', 128) + bytes(16)
    pid4 += fixed('测试😀', 0x208) + struct.pack('<Q', upgrade) + bytes(0x50)
    pid4 += fixed('X00-12345', 128) + fixed('Retail', 128) + fixed('Volume', 128)
    assert len(pid3) == 0xA4 and len(pid4) == 0x4F8
    result = dict(group=group, serial=serial, security=security, upgrade=upgrade, text=text, extended_pid=extended)
    for name, value in [('bytes', data), ('binding', binding), ('binding_id', hashlib.sha256(binding).digest()[:16]), ('phone', phone), ('phone_win7', struct.pack('<Q', short)), ('pid3', pid3), ('pid4', pid4)]:
        result[name] = value.hex()
    return result


if __name__ == '__main__':
    cases = [(0, 0, 0, False), ((1 << 20) - 1, (1 << 30) - 1, (1 << 53) - 1, True), (100055, 1000043, 1338662172562478, False), (1345, 1003020, 6311608238084405, False), (1, 999999, 16384, True)]
    (ROOT / 'key2009.json').write_text(json.dumps([vector(*case) for case in cases], indent=2) + '\n')
