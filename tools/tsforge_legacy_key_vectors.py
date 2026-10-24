#!/usr/bin/env python3
"""PKEY2005 fixtures; Windows CI additionally checks RNG/key text against .NET Framework."""
# Seeded algorithm adapted from Microsoft Reference Source.
# Copyright (c) Microsoft Corporation; MIT: vendor/dotnet-reference/LICENSE.txt.
import hashlib
import json
import struct
import uuid
from tsforge_key_vectors import ROOT, ALPHABET, utf16, fixed, bag, vector, crc, words


def signed(value):
    return (value + (1 << 31)) % (1 << 32) - (1 << 31)


def samples(seed, count):
    big = (1 << 31) - 1
    state = [0] * 56
    mj = 161803398 - (big if seed == -(1 << 31) else abs(seed))
    state[55], mk = mj, 1
    for i in range(1, 55):
        slot = 21 * i % 55
        state[slot] = mk
        mk = signed(mj - mk)
        if mk < 0:
            mk = signed(mk + big)
        mj = state[slot]
    for _ in range(4):
        for i in range(1, 56):
            state[i] = signed(state[i] - state[1 + (i + 30) % 55])
            if state[i] < 0:
                state[i] = signed(state[i] + big)
    a, b = 0, 21
    result = []
    for _ in range(count):
        a, b = a % 55 + 1, b % 55 + 1
        value = signed(state[a] - state[b])
        if value == big:
            value -= 1
        if value < 0:
            value = signed(value + big)
        state[a] = value
        result.append(int(value * (1.0 / big) * 24))
    return result


def legacy(group, serial, security, upgrade, eula, nonce):
    base = vector(group, serial, security, upgrade)
    raw = 'H4X3D' * 4 + ''.join(ALPHABET[i] for i in samples(signed(group * 1000000000 + serial), 5))
    text = '-'.join(raw[i:i + 5] for i in range(0, 25, 5))
    binding = bag([(2, 'SppPkeyBindingProductKey', utf16(text)), (4, 'SppPkeyBindingMiscData', b''), (2, 'SppPkeyBindingAlgorithm', utf16('msft:rm/algorithm/pkey/2005'))])
    if eula == 'OEM':
        high, low, last = 'OEM', ((group // 2) % 100) * 10000 + serial // 100000, serial % 100000
    else:
        high, low, last = f'{serial // 1000000:03}', serial % 1000000, ((group // 2) % 100) * 1000 + nonce
    checksum = 7 - sum(int(c) for c in str(low)) % 7
    pid2 = f'03612-{high}-{low:06}{checksum}-{last:05}'
    assert len(pid2) <= 24
    pid3 = words(0xA4, 3) + pid2.encode().ljust(24, b'\0') + words(group) + b'X00-12345'.ljust(16, b'\0') + bytes(0x6C)
    pid3 += struct.pack('>I', (~crc(pid3[::-1])) & 0xFFFFFFFF)
    phone = uuid.UUID('b8731595-a2f6-430b-a799-fbffb81a8d73').bytes_le + bytes.fromhex(base['phone'])[16:]
    license_type = 2 if eula == 'OEM' else 3 if eula == 'Volume' else 0
    extended = f'03612-{group:05}-{serial // 1000000:03}-{serial % 1000000:06}-{license_type:02}-2052-26100.0000-2982026'
    pid4 = bytearray.fromhex(base['pid4'])
    pid4[8:136] = fixed(extended, 128)
    pid4[-128:] = fixed(eula, 128)
    return dict(group=group, serial=serial, security=security, upgrade=upgrade, eula=eula, nonce=nonce, text=text, pid2=pid2, bytes=base['bytes'],
                binding=binding.hex(), binding_id=hashlib.sha256(binding).digest()[:16].hex(), phone=phone.hex(), phone_win7=base['phone_win7'], pid3=pid3.hex(), pid4=pid4.hex())


if __name__ == '__main__':
    cases = [(0, 0, 0, False, 'Retail', 0), ((1 << 20) - 1, (1 << 30) - 1, 1023, True, 'OEM', 999),
             (206, 123456789, 511, False, 'OEM', 0), (1345, 1003020, 1, False, 'Volume', 123), (1, 999999, 0, True, 'Retail', 999)]
    seeds = [0, 1, -1, -(1 << 31), (1 << 31) - 1, 161803398] + [signed(g * 1000000000 + s) for g, s, *_ in cases]
    output = dict(random=[dict(seed=seed, values=samples(seed, 128)) for seed in seeds], keys=[legacy(*case) for case in cases])
    (ROOT / 'key2005.json').write_text(json.dumps(output, indent=2) + '\n')
