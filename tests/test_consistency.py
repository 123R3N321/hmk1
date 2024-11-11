import sys
import json
from jsonschema import validate
import subprocess
import requests
import re
'''
this test is only good after testing -c command. -d flag to bypass it  
'''
def test_consistency():

    consistency = subprocess.run(
        ['python3', 'main.py', '--consistency', '-d'],
        capture_output=True,
        text=True
    )
    consistency_output = consistency.stdout


    assert re.search(r".*\bpassed\b.*",consistency_output)


if __name__ == "__main__":
    test_consistency()