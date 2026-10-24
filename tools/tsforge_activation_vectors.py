"""Independent BatchActivation request MAC vector (pinned MAS, GPL-3.0-only)."""
from pathlib import Path
import base64, hashlib, hmac, json, re
root=Path(__file__).resolve().parents[1]
source=(root/'vendor/mas/MAS_AIO.cmd').read_text()
section=source.split('MacKey = new byte[64] {',1)[1].split('};',1)[0]
key=bytes(int(v) for v in re.findall(r'\d+',section))
assert key==(root/'vendor/mas/native/tsforge-activation-mac.bin').read_bytes()
iid='1234567890'*6+'123'; epid='PID & <测试😀>\rvalue'
escaped=epid.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('\r','&#xD;')
inner=f'<ActivationRequest xmlns="http://www.microsoft.com/DRM/SL/BatchActivationRequest/1.0"><VersionNumber>2.0</VersionNumber><RequestType>1</RequestType><Requests><Request><PID>{escaped}</PID><IID>{iid}</IID></Request></Requests></ActivationRequest>'
data=inner.encode('utf-16le')
(root/'tests/fixtures/tsforge/activation-ws.json').write_text(json.dumps({'iid':iid,'epid':epid,'digest':base64.b64encode(hmac.new(key,data,hashlib.sha256).digest()).decode(),'request_base64':base64.b64encode(data).decode()},ensure_ascii=False,indent=2)+'\n')
