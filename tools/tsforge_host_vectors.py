"""Independent modern KMSHostCharge counter vector from pinned MAS (GPL-3.0-only)."""
from pathlib import Path
import json, struct, uuid
from tsforge_codec_vectors import crc, pad, words
root=Path(__file__).resolve().parents[1]
def text(value): return (value+'\0').encode('utf-16le')
filetime=134000000000000000
ids=b''.join(struct.pack('<q',filetime-10*(i+1))+uuid.UUID(int=0x00112233445566778899aabbccdd0000+i+1).bytes_le for i in range(25))
counts=bytearray(40);counts[4]=25;counts[24]=25
records=[(4,text('SppBindingLicenseData'),(root/'vendor/mas/native/tsforge-hwid.bin').read_bytes()),(1,b'',words(50)),(1,b'',words(1051200000)),(1,b'',words(25)),(4,b'',ids),(4,b'',bytes(counts))]
result=bytearray()
for kind,key,value in records:
 result+=words(crc(words(0,kind,len(key),len(value))+key+value),kind,len(key),len(value));result+=key;pad(result,8);result+=value;pad(result,8)
(root/'tests/fixtures/tsforge/host-charge.json').write_text(json.dumps({'filetime':filetime,'binding':result.hex()},indent=2)+'\n')
# Vista writes GUID before FILETIME and has a raw header, without a variable bag.
vista=bytearray(44)
vista[:12]=words(50,43200,32)
vista[20]=25;vista[32]=25
for i in range(25):
 vista+=uuid.UUID(int=0x00112233445566778899aabbccdd0000+i+1).bytes_le
 vista+=struct.pack('<q',filetime-10*(i+1))
(root/'tests/fixtures/tsforge/host-charge-vista.json').write_text(json.dumps({'filetime':filetime,'binding':vista.hex()},indent=2)+'\n')
