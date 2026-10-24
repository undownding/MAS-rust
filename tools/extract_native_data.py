"""Extract public MAS lookup/signing data without executing upstream code."""
from pathlib import Path
import re
ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / 'vendor/mas/native'
DEST.mkdir(exist_ok=True)
current = (ROOT / 'vendor/mas/MAS_AIO.cmd').read_text()
legacy = (ROOT / 'vendor/mas/KMS38_Activation.cmd').read_text()
for name, source, label in [('hwid', current, 'hwiddata'), ('kms38', legacy, 'kms38data')]:
    section = source.split('\n:' + label + '\n', 1)[1].split(') do (', 1)[0]
    rows = []
    for line in section.splitlines():
        if re.match(r'^[0-9a-f]{8}-', line):
            rows.append('\t'.join(re.split('_+', line.replace('%f%', ''))))
    (DEST / (name + '.tsv')).write_text('\n'.join(rows) + '\n')
    section = source.split('\n:' + name + 'fallback\n', 1)[1].split(') do (', 1)[0]
    rows = ['\t'.join(re.split('_+', line.replace('%f%', ''))) for line in section.splitlines() if re.match(r'^\d+_', line)]
    (DEST / (name + '-fallback.tsv')).write_text('\n'.join(rows) + '\n')
section = current.split('[byte[]] $key =', 1)[1].split('$rsa =', 1)[0]
blob = bytes(int(x, 16) for x in re.findall(r'0x([0-9A-Fa-f]{2})', section))
assert len(blob) == 596
(DEST / 'ticket-key.blob').write_bytes(blob)
print('Extracted HWID/KMS38 tables, fallbacks and the upstream public signing blob.')

section = current.split('\n:ksdata\n', 1)[1].split(') do (', 1)[0]
rows = []
family = 'windows'
for line in section.splitlines():
    if line.startswith(':: Office'):
        family = 'office'
    if re.match(r'^[0-9a-f]{8}-', line):
        rows.append(family + '\t' + '\t'.join(re.split('_+', line.replace('%f%', ''))))
(DEST / 'online-kms.tsv').write_text('\n'.join(rows) + '\n')
section = current.split('\n:kmsfallback\n', 1)[1].split(') do (', 1)[0]
rows = ['\t'.join(re.split('_+', line.replace('%f%', ''))) for line in section.splitlines() if re.match(r'^\d+_', line)]
(DEST / 'online-kms-fallback.tsv').write_text('\n'.join(rows) + '\n')
section = current.split('\n:_tasksetserv\n', 1)[1].split('\n:_taskgetserv', 1)[0]
servers = []
for line in section.splitlines():
    if line.startswith('set "srvlist='):
        servers.extend(line[len('set "srvlist='):-1].replace('%srvlist%', '').replace('%-%', '').split())
assert len(servers) == 15
(DEST / 'kms-servers.txt').write_text('\n'.join(servers) + '\n')

section = current.split('\n:msiofficedata\n', 1)[1].split(') do (', 1)[0]
rows = ['\t'.join(line.split('_')) for line in section.splitlines() if re.match(r'^(14|15|16)_[0-9a-f]{8}-', line)]
(DEST / 'office-msi.tsv').write_text('\n'.join(rows) + '\n')

section = current.split('\n:ohookdata\n', 1)[1].split(') do (', 1)[0]
rows = ['\t'.join(re.split('_+', line.replace('%f%', ''))) for line in section.splitlines() if re.match(r'^(14|15|16)_[0-9a-f]{8}-', line)]
(DEST / 'ohook.tsv').write_text('\n'.join(rows) + '\n')

# These RSA blobs are public upstream constants, not local machine credentials.
for name in ('PRODUCTION', 'TEST'):
    section = current.split('public static readonly byte[] ' + name + ' = {', 1)[1].split('};', 1)[0]
    blob = bytes(int(x, 16) for x in re.findall(r'0x([0-9A-Fa-f]{2})', section))
    assert len(blob) == 596
    (DEST / ('tsforge-' + name.lower() + '.blob')).write_bytes(blob)

section = current.split('public static readonly byte[] UniversalHWIDBlock =', 1)[1].split('};', 1)[0]
blob = bytes(int(x, 16) for x in re.findall(r'0x([0-9A-Fa-f]{2})', section))
assert len(blob) == 38
(DEST / 'tsforge-hwid.bin').write_bytes(blob)

section = current.split('MacKey = new byte[64] {', 1)[1].split('};', 1)[0]
blob = bytes(int(value) for value in re.findall(r'\d+', section))
assert len(blob) == 64
(DEST / 'tsforge-activation-mac.bin').write_bytes(blob)

for version in (4, 5, 6):
    section = current.split(f'public static readonly byte[] KMSv{version}Response =', 1)[1].split('};', 1)[0]
    blob = bytes(int(value, 16) for value in re.findall(r'0x([0-9a-fA-F]{2})', section))
    assert blob[:4] == bytes([0, 0, version, 0])
    (DEST / f'tsforge-kms-v{version}.bin').write_bytes(blob)

# Preserve table order: current edition names precede legacy aliases for one SKU.
section = current.split('\n:ts_getedition\n', 1)[1].split(') do (', 1)[0]
rows = [line.replace(':', '\t', 1) for line in section.splitlines() if re.fullmatch(r'\d+:[A-Za-z0-9_]+', line)]
assert len(rows) > 180
(DEST / 'tsforge-editions.tsv').write_text('\n'.join(rows) + '\n')

section = current.split('if not defined isThinpc if not defined isltsc for %%# in (', 1)[1].split(') do (', 1)[0]
rows = ['\t'.join(line.split('_', 2)) for line in section.splitlines() if re.match(r'^[0-9a-f]{8}-', line)]
assert len(rows) == 17
(DEST / 'tsforge-esu.tsv').write_text('\n'.join(rows) + '\n')

for label, name, count in [('ts_ohost', 'tsforge-office-host', 6), ('ts_appxlob', 'tsforge-appx', 4)]:
    section = current.split('\n:' + label + '\n', 1)[1].split(') do (', 1)[0]
    rows = ['\t'.join(line.split('_', 1)) for line in section.splitlines() if re.match(r'^[0-9a-f]{8}-', line)]
    assert len(rows) == count
    (DEST / (name + '.tsv')).write_text('\n'.join(rows) + '\n')

section = current.split('\n:tsksdata\n', 1)[1].split(') do (', 1)[0]
rows = ['\t'.join(line.split('_', 2)) for line in section.splitlines() if re.match(r'^(15|16)_', line)]
assert len(rows) > 80
(DEST / 'tsforge-office-conversion.tsv').write_text('\n'.join(rows) + '\n')
