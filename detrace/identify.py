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

import numpy as np
import tensorflow as tf

from detrace.ctx import ctx
from detrace.decrypt import DECIPHERS

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

    return results
