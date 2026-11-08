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

from detrace.ctx import ctx

WORDS_SET = set()

def generate_word_set() -> None:
    """
    Generates the set of possible words using the given dictionary file.

    Returns:
        None
    """

    if WORDS_SET:
        return

    c = ctx()

    with open(c.dictionary_path, 'r', encoding='utf-8') as f:
        loaded_words = {line.strip().lower() for line in f if line.strip()}
        WORDS_SET.clear()
        WORDS_SET.update(loaded_words)

def verify_plaintext(text: str, threshold: float = 0.80) -> bool:
    """
    Verifies if the given text is plaintext as per the given dictionary. The function also compares
    the result with a threshold value. Only if the resulting text has a rate of correct words to
    total words over the threshold, does the function return true.

    Arguments:
        text: str: The potential plaintext.
        threshold: float: Default 0.8.

    Returns:
        bool: True if the condition is met, False if not.
    """

    c = ctx()
    c.logger.info(f"Verifying plaintext: '{text}' ...")

    if not WORDS_SET:
        c.logger.info("Generating word set ...")
        generate_word_set()

    if not text:
        c.logger.warning("Empty text provided for verification.")
        return False

    tokens = [token.strip(".,!?\"'").lower() for token in text.split()]
    word_tokens = [t for t in tokens if t and not t.isdigit()]

    if not word_tokens:
        c.logger.warning("No word tokens found.")
        return False

    valid_count = sum(1 for word in word_tokens if word in WORDS_SET)
    match_ratio = valid_count / len(word_tokens)

    c.logger.info(f"Valid words: {valid_count}/{len(word_tokens)} ({match_ratio:.2%})")

    return match_ratio >= threshold
