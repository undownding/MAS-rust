#!/usr/bin/env python3
"""Reproducible synthetic TSforge vectors using Python cryptography/OpenSSL.

Requires cryptography. Public RSA blobs come from the pinned MAS source.
RSA encryption uses a fixed nonzero PKCS#1 padding string ONLY for fixtures;
production Rust encryption uses OS randomness. No licensing store is accessed.
"""
from pathlib import Path
import hashlib
import hmac
import struct
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / 'tests/fixtures/tsforge'
PAYLOAD = b'independent TSforge envelope fixture\0\xff'


def load_key(production):
    blob = (ROOT / 'vendor/mas/native' / f'tsforge-{production}.blob').read_bytes()
    def number(start, end):
        return int.from_bytes(blob[start:end], 'little')
    return rsa.RSAPrivateNumbers(
        p=number(148, 212), q=number(212, 276), d=number(468, 596),
        dmp1=number(276, 340), dmq1=number(340, 404), iqmp=number(404, 468),
        public_numbers=rsa.RSAPublicNumbers(65537, number(20, 148)),
    ).private_key()


def main():
    DEST.mkdir(parents=True, exist_ok=True)
    for version, number, production, key_length in [
        ('vista', 2, 'production', 16),
        ('win7', 5, 'production', 24),
        ('modern', 3, 'test', 32),
    ]:
        key = load_key(production)
        aes_key = bytes(range(key_length))
        salt = bytes(range(16))
        public = key.public_key().public_numbers()
        encoded = b'\0\x02' + bytes(range(1, 126 - key_length)) + b'\0' + aes_key
        assert len(encoded) == 128
        encrypted_key = pow(int.from_bytes(encoded, 'big'), public.e, public.n).to_bytes(128, 'big')
        assert key.decrypt(encrypted_key, rsa_padding.PKCS1v15()) == aes_key
        signature = key.sign(encrypted_key, rsa_padding.PKCS1v15(), hashes.SHA1())
        digest = hashlib.sha1(salt + PAYLOAD).digest() if version == 'vista' else hmac.digest(salt, PAYLOAD, 'sha1')
        clear = salt + digest + bytes(4) + PAYLOAD
        padder = padding.PKCS7(128).padder()
        padded = padder.update(clear) + padder.finalize()
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(bytes(16))).encryptor()
        encrypted = cipher.update(padded) + cipher.finalize()
        envelope = struct.pack('<I', number) + b'UNTRUSTSTORE' + signature + encrypted_key + encrypted
        (DEST / f'envelope-{version}.bin').write_bytes(envelope)


if __name__ == '__main__':
    main()
