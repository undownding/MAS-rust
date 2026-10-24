"""Independent ZeroCID framing/hash vector from pinned MAS constants (GPL-3.0-only)."""
from pathlib import Path
import hashlib, json, re, struct
root = Path(__file__).resolve().parents[1]
source = (root / 'vendor/mas/MAS_AIO.cmd').read_text()
section = source.split('public static readonly byte[] UniversalHWIDBlock =', 1)[1].split('};', 1)[0]
hwid = bytes(int(v, 16) for v in re.findall(r'0x([0-9a-fA-F]{2})', section))
assert len(hwid) == 38
assert (root / 'vendor/mas/native/tsforge-hwid.bin').read_bytes() == hwid
iid = '1234567890' * 6 + '123'
digest = hashlib.sha256((iid + '\0' + '0' * 48 + '\0').encode('utf-16le')).digest()
def frame(value):
    return struct.pack('<I', len(digest)) + digest + struct.pack('<I', len(value)) + value
(root / 'tests/fixtures/tsforge/phone.json').write_text(json.dumps({
    'iid': iid, 'hash': digest.hex(), 'hwid_cache': frame(hwid).hex(), 'key_cache': frame(bytes([1,2,3])).hex()
}, indent=2) + '\n')
# Windows 7 hashes only the terminated IID; the stored authenticator is 8 bytes.
digest = hashlib.sha256((iid + '\0').encode('utf-16le')).digest()
shortauth = bytes.fromhex('0102030405060708')
(root / 'tests/fixtures/tsforge/phone-win7.json').write_text(json.dumps({
    'iid': iid, 'hash': digest.hex(), 'hwid_cache': frame(hwid).hex(),
    'key_cache': frame(shortauth).hex()
}, indent=2) + '\n')
# Vista uses the first 16 hash bytes and derives auth from fixed PKeyBasicInfo fields.
import base64
digest = hashlib.sha256((iid + '\0').encode('utf-16le')).digest()[:16]
auth = 0x123456789A
group = 12345
basic = bytearray(0x220)
unique = 'prefix&' + base64.b64encode(struct.pack('<Q', auth)).decode()
pid = f'55041-{group}-000-000000-00-0000-0000.0000-0000000'
for offset, text in [(0x120, unique), (0x1a0, pid)]:
    encoded = (text + '\0').encode('utf-16le')
    assert len(encoded) <= 0x80
    basic[offset:offset + len(encoded)] = encoded
shortauth = struct.pack('<Q', auth | (group << 41))
(root / 'tests/fixtures/tsforge/phone-vista.json').write_text(json.dumps({
    'iid': iid, 'basic': basic.hex(), 'phone_data': shortauth.hex(),
    'hwid_cache': frame(hwid).hex(), 'key_cache': frame(shortauth).hex()
}, indent=2) + '\n')
