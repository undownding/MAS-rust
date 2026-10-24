"""Independent modern KMS4k binding/timer vectors from pinned MAS (GPL-3.0-only)."""
from pathlib import Path
import json, re, struct
from tsforge_codec_vectors import crc, pad, words
root=Path(__file__).resolve().parents[1]
source=(root/'vendor/mas/MAS_AIO.cmd').read_text()
def constant(name):
 section=source.split(f'public static readonly byte[] {name} =',1)[1].split('};',1)[0]
 return bytes(int(v,16) for v in re.findall(r'0x([0-9a-fA-F]{2})',section))
def string(text): return (text+'\0').encode('utf-16le')
response=constant('KMSv6Response');hwid=constant('UniversalHWIDBlock')
assert response==(root/'vendor/mas/native/tsforge-kms-v6.bin').read_bytes()
records=[(4,b'',response),(2,b'',string('msft:rm/algorithm/hwid/4.0')),(4,string('SppBindingLicenseData'),hwid),(2,b'',string('massgrave.dev')),(2,b'',string('6969'))]
binding=bytearray()
for kind,key,value in records:
 binding+=words(crc(words(0,kind,len(key),len(value))+key+value),kind,len(key),len(value));binding+=key;pad(binding,8);binding+=value;pad(binding,8)
filetime=134000000000000000
timer=struct.pack('<QQQQ',0,((2**63-1)+17-3)%(2**64),filetime//10000,2147483640*60000)
(root/'tests/fixtures/tsforge/kms4k.json').write_text(json.dumps({'filetime':filetime,'binding':binding.hex(),'timer':timer.hex()},indent=2)+'\n')
