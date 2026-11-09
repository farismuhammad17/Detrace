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

from dataclasses import dataclass, field
from typing import Optional

class PseudoLogger:
    """
    Some commands do not require a full logger, and hence do not take the --log flag. To still
    function with a partial logger, this class provides a very light version of a logger with
    the same functionality (used) by the actual logger.
    """

    def info(self, txt):
        "Prints info text"
        print(f"[INFO] {txt}")
    def warning(self, txt):
        "Prints warning text"
        print(f"[WARNING] {txt}")
    def error(self, txt):
        "Prints error text"
        print(f"[ERROR] {txt}")

@dataclass
class Context:
    """
    Global context used by the program throughout. This is used in place of just passing variables
    around, because a global class felt more intact.
    """

    mode: Optional[str] = None
    model_path: Optional[str] = None
    dictionary_path: Optional[str] = None
    data: Optional[str] = None
    data_file: Optional[str] = None
    data_url: Optional[str] = None
    logger: logging.Logger = field(default_factory=lambda: logging.getLogger("detrace"))

current_ctx: Optional[Context] = None

def set_global_context(ctx: Context) -> None:
    "Sets the given context as the global context"
    global current_ctx
    current_ctx = ctx

def ctx() -> Context:
    "Returns the current global context object"
    if current_ctx is None:
        raise RuntimeError("Context uninitialized.")
    return current_ctx
