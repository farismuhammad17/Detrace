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

import logging
import sys
import argparse
from pathlib import Path

import requests

from detrace.ctx import Context, set_global_context, PseudoLogger

from detrace.train import train
from detrace.identify import nn_identify
from detrace.verify import verify_plaintext

from detrace.encrypt import CIPHERS
from detrace.decrypt import DECIPHERS

CIPHERS_LEN = len(CIPHERS)
DECIPHERS_MAP = {d['name']: [d['func'], d['verifs']] for d in DECIPHERS}

def initial_verifications(logger: logging.Logger) -> bool:
    """
    Verifies the program's integrity before any real functionings. Currently, it does the
    following checks:

        1. If all given CIPHERS are unique
        2. If all given DECIPHERS are unique
        3. If the CIPHERS and DECIPHERS set match

    Arguments:
        logger: logging.Logger: Used in case of an error.

    Returns:
        bool: True if everything is correct, False if not.
    """

    cipher_set = {c['name'] for c in CIPHERS}
    decipher_set = {d['name'] for d in DECIPHERS}

    if len(CIPHERS) != len(cipher_set):
        logger.error("Cipher names are not unique")
        return False

    if len(DECIPHERS) != len(decipher_set):
        logger.error("Decipher names are not unique")
        return False

    if cipher_set != decipher_set:
        logger.error("Cipher and decipher names do not match")
        return False

    return True

def setup_logging(log_file_path: str | Path) -> None:
    """
    Setup global logger object and the file to save the log traces to.

    Arguments:
        log_file_path: str | Path: Path to the log file.

    Returns:
        None
    """

    log_path = Path(log_file_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    if root_logger.handlers:
        return

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_format = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(file_format)
    root_logger.addHandler(file_handler)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_format = logging.Formatter("[%(levelname)s] %(message)s")
    console_handler.setFormatter(console_format)
    root_logger.addHandler(console_handler)

def get_args() -> argparse.Namespace:
    """
    Parse the CLI arguments provided by the user using argparse.

    Returns:
        argparse.Namespace: The arguments passed.
    """

    parser = argparse.ArgumentParser(description="Detrace CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Train
    p_train = subparsers.add_parser("train",
        help="Train the ML model given randomized sample data.")
    p_train.add_argument("--dictionary", type=str, required=True,
        help="File of all possible files, line separated.")
    p_train.add_argument("--size", type=int, required=True,
        help="Size of sample data used to train the model.")
    p_train.add_argument("--epochs", type=int, default=10,
        help="Number of epochs (complete passes of the training algorithm through dataset).")
    p_train.add_argument("--model", type=str, required=True,
        help="Path to store the model file.")
    p_train.add_argument("--log", type=str, default='logs/train.log',
        help="Path to log file.")

    # Identify
    p_identify = subparsers.add_parser("identify",
        help="Ranked cipher picks of the ML model.")
    ident_group = p_identify.add_mutually_exclusive_group(required=True)
    ident_group.add_argument("--text", type=str,
        help="Literal cipher text.")
    ident_group.add_argument("--file", type=str,
        help="Path to file containing cipher text.")
    ident_group.add_argument("--url", type=str,
        help="Remote URL or API endpoint containing the payload.")
    p_identify.add_argument("--model", type=str, required=True,
        help="Path to model file.")
    p_identify.add_argument("--top", type=int, default=1,
        help="Number of ranks to list (value <= 0 lists all).")
    p_identify.add_argument("--log", type=str, default='logs/identify.log',
        help="Path to log file.")

    # Decrypt
    p_decrypt = subparsers.add_parser("decrypt",
        help="Decipher given cipher text using iterative ML processing.")
    decrypt_group = p_decrypt.add_mutually_exclusive_group(required=True)
    decrypt_group.add_argument("--text", type=str,
        help="Literal cipher text.")
    decrypt_group.add_argument("--file", type=str,
        help="Path to file containing cipher text.")
    decrypt_group.add_argument("--url", type=str,
        help="Remote URL or API endpoint containing the payload.")
    p_decrypt.add_argument("--dictionary", type=str, required=True,
        help="Path to dictionary file.")
    p_decrypt.add_argument("--model", type=str, required=True,
        help="Path to model file.")
    p_decrypt.add_argument("--log", type=str, default='logs/decrypt.log',
        help="Path to log file.")

    # Direct decrypt
    p_direct = subparsers.add_parser("direct-decrypt",
        help="Manually decode text using a specific cipher without the NN.")
    direct_group = p_direct.add_mutually_exclusive_group(required=True)
    direct_group.add_argument("--text", type=str,
        help="Literal cipher text.")
    direct_group.add_argument("--file", type=str,
        help="Path to file containing cipher text.")
    direct_group.add_argument("--url", type=str,
        help="Remote URL or API endpoint containing the payload.")
    p_direct.add_argument("--cipher", type=str, required=True,
        help="Name of the cipher.")
    p_direct.add_argument("--dictionary", type=str, required=True,
        help="Path to dictionary file.")
    p_direct.add_argument("--threshold", type=float, default=0.8,
        help="Maximum threshold when checking output.")

    # List
    subparsers.add_parser("list",
        help="List all supported ciphers and encodings registered in detrace.")

    return parser.parse_args()

def get_data(args: argparse.Namespace, logger: logging.Logger | PseudoLogger) -> str:
    """
    Parses the arguments provided by the user to get the actual data. If the data was passed in
    as literal text, the program stores just that. If a file was provided, the program stores the
    contents of that file. If a URL was passed, it sends a GET request to the URL with a 10 second
    timeout, the payload of which is the data stored.

    Arguments:
        args: argparse.Namespace: The raw arguments parsed.

    Returns:
        str: The data found.
    """

    data = None

    if getattr(args, "text", False):
        data = args.text

    elif getattr(args, "file", False):
        file_path = Path(args.file)
        if not file_path.is_file():
            logger.error(f"File '{args.file}' not found.")
            return ''
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            data = f.read().strip()

    elif getattr(args, "url", False):
        try:
            response = requests.get(args.url, timeout=10)
            response.raise_for_status()
            data = response.text.strip()
            logger.info(f"Fetched payload from '{args.url}'")

        except requests.exceptions.Timeout:
            logger.error(f"The request to '{args.url}' timed out (exceeded 10s limit).")
            return ''

        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code if e.response is not None else "Unknown"
            logger.error(f"HTTP error occurred for '{args.url}': Status code {status_code}")
            return ''

        except requests.exceptions.ConnectionError:
            logger.error(f"Failed to connect to '{args.url}'.")
            return ''

        except requests.exceptions.RequestException as e:
            logger.error(f"An error occurred while making the request to '{args.url}': {e}")
            return ''

    return data

def decrypt(c: Context) -> None:
    """
    Main function to decrypt a given ciphertext from the context by iterating through an Machine
    learning algorithm. The function uses the context object passed to take the data and check
    if the given text is plaintext, if not, identify the cipher used using the Neural Network.
    The NN will provide back a list of possible outputs, ranked from most probable to least. All
    options are exhausted till the cipher is solved or not.

    The Cipher Text will remain unsolved if none of the program's cipher are capable to solve the
    given cipher. This can be either because the program lacks support for that cipher or the
    function the program has for the cipher is too weak or incapable to solve it.

    The output is logged and finally printed in a clean table at the end, with the status as well
    as the process used to decipher.

    Arguments:
        c: Context: The context object with data to decipher

    Returns:
        None
    """

    curr = c.data
    preds = [1]
    trace = []
    solved = False

    while preds:
        if verify_plaintext(curr):
            c.logger.info(f"Solution: {curr}")
            solved = True
            break

        preds = nn_identify(curr, n=CIPHERS_LEN)

        while True:
            if not preds:
                c.logger.error("Unable to solve")
                break

            pred = preds.pop(0)
            guess = DECIPHERS[pred['id']]['func'](curr)
            c.logger.info(f"Trying {pred['name']}...")

            if guess and guess != curr:
                trace.append({
                    "cipher": pred['name'],
                    "output": guess
                })

                curr = guess
                break

            c.logger.info(f"{pred['name']} failed on {curr}")

    print(f"\nTarget: {c.data_url or c.data_file or c.data}")
    print("=" * 80)
    print(f" Layers:     {len(trace)}")
    print(f" Status:     {'Success' if solved else 'Failed'}")
    print("-" * 80)

    if trace:
        for i, step in enumerate(trace, 1):
            print(f" [{i}] {step['cipher'].upper():<12} -> {step['output']}")
    else:
        print(" No transformations were applied (input was already plaintext or invalid).")

    print("=" * 80)
    if solved:
        print(f" SOLUTION: {curr}")
    else:
        print(" SOLUTION: Unable to resolve.")
    print("=" * 80 + "\n")

def main() -> None:
    """
    Detrace Main function

    Returns:
        None
    """

    args = get_args()

    logger = PseudoLogger()
    if hasattr(args, "log"):
        setup_logging(args.log)
        logger = logging.getLogger(__name__)
        logger.info("Running: %s", " ".join(sys.argv))

    verifs = initial_verifications(logger)
    if not verifs:
        return

    data = get_data(args, logger)

    ctx = Context(
        mode=args.command,
        model_path=getattr(args, "model", ''),
        dictionary_path=getattr(args, "dictionary", ''),
        data=data,
        data_file=getattr(args, "file", ''),
        data_url=getattr(args, "url", ''),
        logger=logger
    )
    set_global_context(ctx)

    if not ctx.model_path.endswith('.keras'):
        ctx.model_path += '.keras'

    match args.command:
        case "train":
            train(args.size, args.epochs)

        case "identify":
            n = args.top
            if n <= 0:
                n = CIPHERS_LEN
            res = nn_identify(data, n=n)
            out = ''
            for r in res:
                rank_str = f" RANK {r['rank']} "
                out += '-' * 3 + rank_str + '-' * (77 - len(rank_str)) + '\n'
                out += f"Rank: {r['rank']}\n"
                out += f"Name: {r['name']}\n"
                out += f"Confidence: {r['confidence'] * 100:.2f}%\n"
            out += '-' * 80
            print(out)

        case "decrypt":
            decrypt(ctx)

        case "direct-decrypt":
            if args.cipher not in DECIPHERS_MAP:
                print(f"Unknown cipher: '{args.cipher}'.")
                return

            if DECIPHERS_MAP[args.cipher][1]:
                print(DECIPHERS_MAP[args.cipher][0](data,
                    getattr(args, "threshold", 0.8)))
            else:
                print(DECIPHERS_MAP[args.cipher][0](data))

        case "list":
            for entry in DECIPHERS:
                print(entry['name'])

        case _:
            raise ValueError(f"Unknown command: '{args.command}'")

if __name__ == '__main__':
    main()
