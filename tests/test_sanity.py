import sys
import os
import subprocess
import json
import pytest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from main import main

'''
only works assuming debug mode is tested
'''
def test_main_sanity(mocker):
    # again, we are assuming debug mode is tested thoroughly
    mocker.patch("sys.argv", ['main.py', '-d'])
    get_consistency_data_func = mocker.patch("main.get_consistency_data")
    get_consistency_data_func.return_value = ('dummy',999999999999999,
                                              "57cad27753aa95e75cf661e1b0e9e95ead65a92eb2bab495011b4632a1b75d12")
    main()

    target_func = mocker.patch("main.verify_consistency")
    assert not target_func.called
if __name__ == "__main__":
    mocker = mock.MagicMock()
    test_main_sanity(mocker)