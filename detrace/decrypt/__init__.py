"""
Copyright 2026 Faris Muhammad

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import base64
import urllib.parse
from detrace.verify import WORDS_SET, verify_plaintext, generate_word_set

def decrypt_atbash(ciphertext: str) -> str:
    result = []
    for char in ciphertext:
        if char.isalpha():
            if char.isupper():
                result.append(chr(ord('Z') - (ord(char) - ord('A'))))
            else:
                result.append(chr(ord('z') - (ord(char) - ord('a'))))
        else:
            result.append(char)
    return "".join(result)

def decrypt_base32(ciphertext: str) -> str:
    try:
        padding_needed = len(ciphertext) % 8
        padded = ciphertext + "=" * ((8 - padding_needed) % 8)
        decoded_bytes = base64.b32decode(padded.encode('utf-8'), casefold=True)
        return decoded_bytes.decode('utf-8')
    except Exception:
        return ""

def decrypt_base64(ciphertext: str) -> str:
    try:
        padding_needed = len(ciphertext) % 4
        padded = ciphertext + "=" * ((4 - padding_needed) % 4)
        decoded_bytes = base64.b64decode(padded.encode('utf-8'), validate=True)
        return decoded_bytes.decode('utf-8')
    except Exception:
        return ""

def decrypt_caesar(ciphertext: str, threshold: float = 0.8) -> str:
    for shift in range(1, 26):
        decrypted_chars = []
        for char in ciphertext:
            if char.isalpha():
                ascii_offset = ord('A') if char.isupper() else ord('a')
                shifted = chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
                decrypted_chars.append(shifted)
            else:
                decrypted_chars.append(char)

        candidate = "".join(decrypted_chars)
        if verify_plaintext(candidate, threshold):
            return candidate

    return ""

def decrypt_hex(ciphertext: str) -> str:
    try:
        decoded_bytes = bytes.fromhex(ciphertext)
        return decoded_bytes.decode('utf-8')
    except Exception:
        return ""

def decrypt_reverse(ciphertext: str) -> str:
    return ciphertext[::-1]

def decrypt_url(ciphertext: str) -> str:
    try:
        return urllib.parse.unquote(ciphertext)
    except Exception:
        return ""

def decrypt_vigenere(ciphertext: str, threshold: float = 0.8) -> str:
    def _vigenere_shift(text: str, key: str, decrypt: bool = True) -> str:
        result = []
        key_length = len(key)
        key_index = 0
        direction = -1 if decrypt else 1
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                shift = (ord(key[key_index % key_length].lower()) - ord('a')) * direction
                result.append(chr((ord(char) - base + shift) % 26 + base))
                key_index += 1
            else:
                result.append(char)
        return "".join(result)

    generate_word_set()
    for word in WORDS_SET:
        if 3 <= len(word) <= 6: # Test reasonable key lengths for performance
            candidate = _vigenere_shift(ciphertext, word, decrypt=True)
            if verify_plaintext(candidate, threshold):
                return candidate
    return ""

DECIPHERS = [
    {'name': 'atbash', 'func': decrypt_atbash, 'verifs': False},
    {'name': 'base32', 'func': decrypt_base32, 'verifs': False},
    {'name': 'base64', 'func': decrypt_base64, 'verifs': False},
    {'name': 'caesar_cipher', 'func': decrypt_caesar, 'verifs': True},
    {'name': 'hex', 'func': decrypt_hex, 'verifs': False},
    {'name': 'reverse', 'func': decrypt_reverse, 'verifs': False},
    {'name': 'url_encode', 'func': decrypt_url, 'verifs': False},
    {'name': 'vigenere', 'func': decrypt_vigenere, 'verifs': True},
]

DECIPHERS.sort(key=lambda x: x['name'])
