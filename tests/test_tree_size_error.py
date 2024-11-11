import sys
import os
import subprocess
import json
from json import JSONDecodeError

import pytest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from main import main

'''
make sure this is a greater size
'''
def get_tree_size():
    checkpoint = subprocess.run(
        ['python3', 'main.py', '-c'],
        capture_output=True,
        text=True
    )
    output = checkpoint.stdout
    output_lines = output.strip().splitlines()
    filtered_output = '\n'.join(output_lines[:-2])  # Exclude the last 2 lines
    data = json.loads(filtered_output)
    rootHash = data["rootHash"]
    treeID = data["treeID"]
    treeSize = str(data["treeSize"])
    return rootHash, treeID, treeSize


'''
only works assuming debug mode is tested
'''
def test_main_sanity(mocker):
    # again, we are assuming debug mode is tested thoroughly
    mocker.patch("sys.argv", ['main.py', '--inclusion','0','-d'])

    mocker.patch("main.get_consistency_data", return_value=(get_tree_size()[0], get_tree_size()[1],0))
    main()
if __name__ == "__main__":
    mocker = mock.MagicMock()
    test_main_sanity(mocker)