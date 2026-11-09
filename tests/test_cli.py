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

import shlex
import subprocess
from pathlib import Path

import pytest

BASE_DIR = Path(__file__).parent
INPUT_DIR = BASE_DIR / "input"
EXPECTED_DIR = BASE_DIR / "expected"

input_files = sorted(INPUT_DIR.glob("*.txt"))

@pytest.mark.parametrize("input_file", input_files, ids=lambda p: p.stem)
def test_cli(input_file):
    test_id = input_file.stem
    expected_file = EXPECTED_DIR / f"{test_id}.txt"

    command_line = input_file.read_text(encoding="utf-8").strip()
    args = shlex.split(command_line)

    result = subprocess.run(
        args,
        text=True,
        capture_output=True,
        check=False
    )

    actual_output = result.stdout.strip()
    expected_output = expected_file.read_text(encoding="utf-8").strip()

    assert expected_output in actual_output, (
        f"\n--- Expected result not found in actual output ---\n"
        f"Expected output:\n{expected_output}\n"
        f"Actual output:\n{actual_output}\n"
    )

    assert result.returncode == 0
