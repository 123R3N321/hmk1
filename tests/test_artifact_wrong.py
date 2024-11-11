import sys
import os
import pytest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from main import main

def test_artifact_wrong(mocker):
    mocker.patch("sys.argv",['main.py', '--inclusion', "132216490", "--artifact", "bad_file_name"])
    with pytest.raises(FileNotFoundError):
        main()
    # assert True   # last step is automatic

if __name__ == "__main__":
    mocker = mock.MagicMock()
    test_artifact_wrong(mocker)