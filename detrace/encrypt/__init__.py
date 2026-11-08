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

import random
import base64
import urllib.parse
import string

def encrypt_caesar(text: str, shift: int) -> str:
    result = []
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - base + shift) % 26 + base))
        else:
            result.append(char)
    return "".join(result)

def encrypt_base64(text: str) -> str:
    return base64.b64encode(text.encode('utf-8')).decode('utf-8')

def encrypt_base32(text: str) -> str:
    return base64.b32encode(text.encode('utf-8')).decode('utf-8')

def encrypt_atbash(text: str) -> str:
    result = []
    for char in text:
        if char.isalpha():
            if char.isupper():
                result.append(chr(ord('Z') - (ord(char) - ord('A'))))
            else:
                result.append(chr(ord('z') - (ord(char) - ord('a'))))
        else:
            result.append(char)
    return "".join(result)

def encrypt_url(text: str) -> str:
    return urllib.parse.quote(text)

def encrypt_reverse(text: str) -> str:
    return text[::-1]

def encrypt_vigenere(text: str, key: str) -> str:
    result = []
    key_length = len(key)
    key_index = 0
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_index % key_length].lower()) - ord('a')
            result.append(chr((ord(char) - base + shift) % 26 + base))
            key_index += 1
        else:
            result.append(char)
    return "".join(result)

def encrypt_hex(text: str) -> str:
    return text.encode('utf-8').hex()

CIPHERS = [
    {'name': 'atbash', 'func': encrypt_atbash, 'rkey': None},
    {'name': 'base32', 'func': encrypt_base32, 'rkey': None},
    {'name': 'base64', 'func': encrypt_base64, 'rkey': None},
    {'name': 'caesar_cipher', 'func': encrypt_caesar, 'rkey': lambda: (random.randint(1, 25),)},
    {'name': 'hex', 'func': encrypt_hex, 'rkey': None},
    {'name': 'reverse', 'func': encrypt_reverse, 'rkey': None},
    {'name': 'url_encode', 'func': encrypt_url, 'rkey': None},
    {'name': 'vigenere', 'func': encrypt_vigenere,
        'rkey': lambda:("".join(random.choices(string.ascii_lowercase, k=random.randint(4, 8))),)},
]

CIPHERS.sort(key=lambda x: x['name'])
