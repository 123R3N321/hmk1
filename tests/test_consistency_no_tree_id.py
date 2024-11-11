import sys
import os
import pytest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from main import main

def test_missing_root_hash_argument(mocker):
    # Mock sys.argv to simulate the command-line input with --root-hash missing its argument
    mocker.patch("sys.argv", ['python3', 'main.py', '--consistency', '--tree-id', '--tree-size', '26140959', '--root-hash','57cad27753aa95e75cf661e1b0e9e95ead65a92eb2bab495011b4632a1b75d12'])
    # Expect the program to raise a SystemExit due to argument parsing error
    with pytest.raises(SystemExit):
        main()

if __name__ == "__main__":
    mocker = mock.MagicMock()
    test_missing_root_hash_argument(mocker)