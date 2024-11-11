import json
from jsonschema import validate
import subprocess

checkpoint_schema = {
    "type": "object",
    "properties": {
        "inactiveShards": {"type": "array"},
        "rootHash": {"type": "string"},
        "signedTreeHead": {"type": "string"},
        "treeID": {"type": "string"},
        "treeSize": {"type": "integer"}
    },
    "required": ["inactiveShards", "rootHash", "signedTreeHead", "treeID", "treeSize"]
}

def test_checkpoint():
    result = subprocess.run(
        ['python3', 'main.py', '-c'],
        capture_output=True,
        text=True
    )
    output = result.stdout

    output_lines = output.strip().splitlines()
    filtered_output = '\n'.join(output_lines[:-2])  # Exclude the last 2 lines

    data = json.loads(filtered_output)

    validate(instance=data, schema=checkpoint_schema)

if __name__ == "__main__":
    test_checkpoint()