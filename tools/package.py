"""Package a locally built Windows executable with docs and corresponding source."""
from pathlib import Path
import hashlib
import shutil
import tomllib
import zipfile

root = Path(__file__).resolve().parents[1]
version = tomllib.loads((root / 'Cargo.toml').read_text())['package']['version']
exe = root / 'target/x86_64-pc-windows-gnu/release/mas-rust.exe'
if not exe.is_file():
    exe = root / 'target/release/mas-rust.exe'
if not exe.is_file():
    raise SystemExit('Build the Windows release executable first.')
out = root / 'dist'
out.mkdir(exist_ok=True)
shutil.copy2(exe, out / 'mas-rust.exe')
source = [root / p for p in ['Cargo.toml', 'Cargo.lock', 'build.rs', 'README.md', 'LICENSE', '.gitignore', '.gitattributes']]
for folder in ['src', 'assets', 'tools', 'vendor', '.github', 'screenshots', 'docs', 'tests']:
    source.extend(p for p in (root / folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts)
package = out / f'mas-rust-v{version}-windows-x64.zip'
with zipfile.ZipFile(package, 'w', zipfile.ZIP_DEFLATED) as archive:
    archive.write(exe, 'mas-rust.exe')
    for name in ['LICENSE', 'README.md', 'vendor/mas/NOTICE.md']:
        archive.write(root / name, name)
    for folder in ['assets', 'screenshots', 'docs']:
        for path in (root / folder).rglob('*'):
            if path.is_file():
                archive.write(path, str(path.relative_to(root)))
    for path in source:
        archive.write(path, 'source/' + str(path.relative_to(root)))
with zipfile.ZipFile(package) as archive:
    assert archive.testzip() is None
shutil.copy2(package, out / 'mas-rust-windows-x64.zip')
files = [out / 'mas-rust.exe', package, out / 'mas-rust-windows-x64.zip']
(out / 'SHA256SUMS').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in files))
print(f'{package}: {package.stat().st_size:,} bytes')
