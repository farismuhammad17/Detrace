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

import os
import random

import numpy as np
import tensorflow as tf
from tensorflow.keras import layers, models

from detrace.ctx import ctx

from detrace.encrypt import CIPHERS

def generate_plaintext_dataset(size: int, dictionary_path: str) -> list[str]:
    """
    Creates synthetic random data, using the dictionary file provided,
    used to train the model.

    Arguments:
        size: int: Size of output data set
        dictionary_path: str: Path to the dictionary.txt file

    Returns:
        list[str]: Dataset of synthetic random data
    """

    if not os.path.exists(dictionary_path):
        raise FileNotFoundError(f"Dictionary file not found at: {dictionary_path}")

    with open(dictionary_path, "r", encoding="utf-8") as f:
        words = [line.strip() for line in f if line.strip()]

    dataset = []

    def synthesize_plaintext() -> str:
        word_count = random.randint(3, 12)
        selected_words = random.choices(words, k=word_count)
        text = " ".join(selected_words)

        if random.random() > 0.4:
            text = text.capitalize()
        if random.random() > 0.7:
            text += f" {random.randint(10, 999)}"

        return text

    for _ in range(size):
        dataset.append(synthesize_plaintext())

    del words

    return dataset

def encrypt_dataset(dataset: list[str]) -> tuple[list[str], list[int]]:
    """
    Manipulates the given dataset of random plaintext using a random cipher from the CIPHERS.
    The CIPHERS list also comes with a 'rkey' function that generates a random key that can be
    fed into the ciphering function. This generates a list of randomised cipher data, and the
    actual cipher used is stored alongside inside the second list.

    Arguments:
        dataset: list[str]: The list of plaintext.

    Returns:
        x, y = tuple[list[str], list[int]]
        x[i]: The randomly ciphered text.
        y[i]: The label of the cipher used on x[i].
    """

    x = []
    y = []

    for text in dataset:
        chosen_cipher = random.choice(CIPHERS)
        label = CIPHERS.index(chosen_cipher)

        rkey_gen = chosen_cipher.get('rkey')
        if rkey_gen is not None:
            keys = rkey_gen()
            ciphertext = chosen_cipher['func'](text, *keys)
        else:
            ciphertext = chosen_cipher['func'](text)

        x.append(ciphertext)
        y.append(label)

    return x, y

def train(size: int, epochs: int) -> None:
    """
    The actual training function that creates the model and saves it based on the context given
    by the user.

    Arguments:
        size: int: Size of training data
        epochs: int: Number of epochs used (complete passes of the training algorithm through
            the dataset)

    Returns:
        None
    """

    c = ctx()

    c.logger.info("Generating plaintext dataset.")
    dataset = generate_plaintext_dataset(size, c.dictionary_path)

    c.logger.info("Generating encrypted dataset.")
    x, y = encrypt_dataset(dataset)

    c.logger.info("Preparing data for TensorFlow ...")
    x_tensor = tf.constant(x)
    y_train = np.array(y)

    c.logger.info("Building neural network architecture ...")
    max_features = 2000  # Max vocabulary size
    max_len = 120        # Truncate/pad text length

    vectorize_layer = layers.TextVectorization(
        max_tokens=max_features,
        output_mode='int',
        output_sequence_length=max_len
    )

    vectorize_layer.adapt(x_tensor)

    model = models.Sequential([
        layers.Input(shape=(), dtype=tf.string),
        vectorize_layer,
        layers.Embedding(input_dim=max_features, output_dim=64),
        layers.GlobalAveragePooling1D(),
        layers.Dense(64, activation='relu'),
        layers.Dense(len(CIPHERS), activation='softmax')
    ])

    c.logger.info("Compiling model ...")
    model.compile(
        optimizer='adam',
        loss='sparse_categorical_crossentropy',
        metrics=['accuracy']
    )

    model.summary()

    c.logger.info("Training model ...")
    model.fit(x_tensor, y_train, epochs=epochs, batch_size=32)

    os.makedirs(os.path.dirname(c.model_path), exist_ok=True)
    model.save(c.model_path)

    c.logger.info(f"Model successfully saved to '{c.model_path}'.")
