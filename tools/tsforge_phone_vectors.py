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
