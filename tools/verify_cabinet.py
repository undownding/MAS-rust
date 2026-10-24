"""Verify Rust CAB fixtures using independent libarchive (Linux).
Generate with MAS_CAB_FIXTURE_DIR=<dir> cargo test cabinet_blocks_roundtrip.
Usage: python3 tools/verify_cabinet.py <dir>
"""
import sys
import ctypes as C
from pathlib import Path
lib=C.CDLL('libarchive.so.13')
lib.archive_read_new.restype=C.c_void_p
for name in ['archive_read_support_format_cab','archive_read_support_filter_all','archive_read_free']:
 getattr(lib,name).argtypes=[C.c_void_p]
lib.archive_read_open_filename.argtypes=[C.c_void_p,C.c_char_p,C.c_size_t]
lib.archive_read_next_header.argtypes=[C.c_void_p,C.POINTER(C.c_void_p)]
lib.archive_read_data.argtypes=[C.c_void_p,C.c_void_p,C.c_size_t];lib.archive_read_data.restype=C.c_ssize_t
lib.archive_entry_pathname.argtypes=[C.c_void_p];lib.archive_entry_pathname.restype=C.c_char_p
lib.archive_error_string.argtypes=[C.c_void_p];lib.archive_error_string.restype=C.c_char_p
fixtures = sorted(Path(sys.argv[1]).glob('*.cab'))
assert fixtures, 'No CAB fixtures found'
for cab in fixtures:
 a=lib.archive_read_new()
 try:
  assert lib.archive_read_support_format_cab(a)==0
  assert lib.archive_read_support_filter_all(a)==0
  assert lib.archive_read_open_filename(a,str(cab).encode(),10240)==0
  entry=C.c_void_p()
  assert lib.archive_read_next_header(a,C.byref(entry))==0,lib.archive_error_string(a)
  assert lib.archive_entry_pathname(entry)==b'repair.log'
  result=bytearray(); buffer=C.create_string_buffer(65536)
  while True:
   size=lib.archive_read_data(a,buffer,len(buffer))
   assert size>=0,lib.archive_error_string(a)
   if size==0:break
   result.extend(buffer.raw[:size])
  assert result==cab.with_suffix('.raw').read_bytes()
  assert lib.archive_read_next_header(a,C.byref(entry))==1
  print(cab.name,len(result),'verified by libarchive')
 finally:lib.archive_read_free(a)
