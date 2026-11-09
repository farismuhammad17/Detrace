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

import re

import numpy as np
import tensorflow as tf

from detrace.ctx import ctx
from detrace.decrypt import DECIPHERS

HASH_PATTERNS = {
    "Adler-32 / CRC32": re.compile(r"^[a-fA-F0-9]{8}$"),
    "MD5 / NTLM / LM / MD4": re.compile(r"^[a-fA-F0-9]{32}$"),
    "SHA-1 / RIPEMD-160": re.compile(r"^[a-fA-F0-9]{40}$"),
    "MySQL 4.1+": re.compile(r"^\*[a-fA-F0-9]{40}$"),
    "Tiger-192": re.compile(r"^[a-fA-F0-9]{48}$"),
    "SHA-224 / SHA3-224": re.compile(r"^[a-fA-F0-9]{56}$"),
    "SHA-256 / SHA3-256 / BLAKE2s": re.compile(r"^[a-fA-F0-9]{64}$"),
    "SHA-384 / SHA3-384": re.compile(r"^[a-fA-F0-9]{96}$"),
    "SHA-512 / SHA3-512 / Whirlpool / BLAKE2b": re.compile(r"^[a-fA-F0-9]{128}$"),
    "MD5 Crypt": re.compile(r"^\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$"),
    "SHA-256 Crypt": re.compile(r"^\$5\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}$"),
    "SHA-512 Crypt": re.compile(r"^\$6\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}$"),
    "Bcrypt": re.compile(r"^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$"),
    "Argon2": re.compile(r"^\$argon2(id|i|d)\$.*$"),
    "PBKDF2": re.compile(r"^\$pbkdf2-(sha1|sha256|sha512)\$"),
}

def hash_identify(ciphertext: str) -> str | None:
    """
    Helper to check if a string matches known hash patterns. It is possible that the given cipher
    happens to match the regex pattern for a known hash. If so, it might indicate that the cipher
    cannot be solved, since hashes are designed to be one way.

    Arguments:
        ciphertext: str: The potential hash

    Returns:
        str | None: A result, if found.
    """

    cleaned = ciphertext.strip()
    for hash_name, pattern in HASH_PATTERNS.items():
        if pattern.match(cleaned):
            return hash_name

    return None

def nn_identify(ciphertext: str, n: int = 1) -> list[dict]:
    """
    Runs the neural network model to return the top 'n' predictions of the model on the given
    cipher text. The program returns the data in a structured list of dictionaries.

    Arguments:
        ciphertext: str: The cipher text to analyse.
        n: int: Default 1. The size of the output list.

    Returns:
        list[dict]: Each dictionary is of the following format: {
            'rank': int: The rank the current prediction is.
            'id': int: The label id of the cipher predicted.
            'name': str: Name of the predicted cipher.
            'confidence': float [0, 1]: How sure the Neural Network is.
        }
    """

    c = ctx()

    matched_hash = hash_identify(ciphertext)

    c.logger.info(f"Loading model '{c.model_path}' ...")
    model = tf.keras.models.load_model(c.model_path)

    input_data = tf.constant([ciphertext])

    preds = model.predict(input_data)[0]
    top_indices = np.argsort(preds)[-n:][::-1]

    results = []
    for rank, pred_id in enumerate(top_indices, start=1):
        confidence = preds[pred_id]
        pred_name = DECIPHERS[pred_id]['name']

        c.logger.info(f"[{rank}] Prediction: {pred_name} ({pred_id}) {confidence * 100:.2f}%")

        results.append({
            'rank': rank,
            'id': int(pred_id),
            'name': pred_name,
            'confidence': float(confidence)
        })

    if matched_hash:
        c.logger.warning(f"Potential Hash: {matched_hash}")

    return results
