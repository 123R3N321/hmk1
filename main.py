'''
This is a simple use case of sigstore cosign.
The code is tested with signing a single artifact
at log index 132216490
'''

import ast
import json
import argparse
import re  # because Im lazy
import base64

import requests

from util import extract_public_key, verify_artifact_signature
from merkle_proof import DefaultHasher, verify_consistency, verify_inclusion, compute_leaf_hash

secret = "AIzaSyCwEro-wQ6YUNcA1ozA9FQev-DyJp3t2EQ"
# api urls
LOG_ENTRY_URL = "https://rekor.sigstore.dev/api/v1/log/entries?logIndex="


def get_checkpoint():
    """
    Fetch the latest checkpoint from the Rekor API and print it out.

    retrieves the latest stable checkpoint from the Rekor API,
    formats it as pretty-printed JSON, and prints it to the console along
    with a message for cross-checking an artifact.
    """
    try:
        checkpoint_url = 'https://rekor.sigstore.dev/api/v1/log?stable=true'
        checkpoint = requests.get(checkpoint_url, timeout=10).json()
        print(json.dumps(checkpoint, indent=4))
        print("\nAbove is the latest checkpoint info, use it to cross-check your artifact!")
    except requests.exceptions.Timeout:
        print("Request timed out. Please try again later.")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")


def get_log_entry(log_index, debug=False):
    """
    Fetch the raw JSON of the log entry from the Rekor API.

    Parameters:
    log_index (int/str): The index of the log entry to retrieve.
    debug (bool): If True, writes the raw entry to a file for debugging.

    Returns:
    dict: The log entry data in JSON format.
    """
    try:
        raw_entry = requests.get(f'{LOG_ENTRY_URL}{log_index}',
                                 timeout=10).json()
        if debug:
            with open("raw_log_entry.json", 'w', encoding='utf-8') as f:
                json.dump(raw_entry, f, ensure_ascii=False, indent=4)
        return raw_entry
    except requests.exceptions.Timeout:
        print("Request timed out. Please try again later.")
        return "Time Out"
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        return "Unknown Error"


def inlclusion_arg_sane(log_index_arg, artifact_arg):
    '''
    checks the sanity of the arguments
    return false if not sane
    '''
    return (isinstance(log_index_arg, int) and
            log_index_arg > 0 and
            isinstance(artifact_arg, str) and
            len(artifact_arg) > 0)


def consistency_arg_sane(tree_id, tree_size, root_hash):
    '''
    checks sanity of arguments
    return false if not sane
    note that I am not making sure tree-id is only numerical
    '''

    return (isinstance(tree_id, str) and
            len(tree_id) > 0 and
            isinstance(tree_size, int) and
            tree_size > 0 and
            isinstance(root_hash, str) and
            len(root_hash) > 0)


def get_consistency_data(current_tree_size):
    """
    Fetch the consistency proof and related data from the Rekor API.

    Parameters:
    current_tree_size (int): The current size of the Merkle tree.

    Returns:
    tuple: A tuple containing proof hashes, checkpoint root hash,
           checkpoint tree ID, checkpoint tree size, and checkpoint root hash.
    """
    checkpoint_response_url = \
        "https://rekor.sigstore.dev/api/v1/log?stable=true"

    try:
        # Fetch the latest checkpoint data
        checkpoint_response = requests.get(checkpoint_response_url, timeout=10)
        checkpoint_response_data = checkpoint_response.json()

        checkpoint_root_hash = checkpoint_response_data['rootHash']  # str
        # checkpoint_tree_id = checkpoint_response_data['treeID']  # str
        checkpoint_tree_size = checkpoint_response_data['treeSize']  # int

        # Build the URL for fetching the proof data
        proof_url = (
            f"https://rekor.sigstore.dev/api/v1/log/proof"
            f"?firstSize={int(checkpoint_tree_size)}"
            f"&lastSize={int(current_tree_size)}"
            # f"&treeID={str(checkpoint_tree_id)}"
        )

        # Fetch the proof data
        proof_response = requests.get(proof_url, timeout=10)
        proof_response_data = proof_response.json()
        proof_hashes = proof_response_data['hashes']

        return (proof_hashes,
                checkpoint_tree_size,
                checkpoint_root_hash)

    except requests.exceptions.Timeout:
        print("Request timed out. Please try again later.")
        return ("Time Out", -1, -1, -1)
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        return ("Unknown Error", -1, -1, -1)


def signature_inclusion_proof(entry):
    '''
    parses all possible data from just log entry
    '''
    data = proof_log_index = tree_size = leaf_hash = hashes = root_hash = None
    for i in entry:  # because data is a single key-val pair
        # extract some data before decoding, see raw_log_entry.json
        leaf_hash = compute_leaf_hash(entry[i]['body'])
        # hashes is the proof
        checkpoint_data = entry[i]['verification']['inclusionProof']['checkpoint']
        # we only need tree id from this part, as size and root hash are nicely given below
        pattern = r'- (.*?)\n'  # the weird format. What can I say
        match = re.search(pattern, checkpoint_data)
        if match:
            tree_id = match.group(1).strip()
            print(f"successful tree id extraction:{tree_id}")
        else:
            print("WARNING: no tree id found")

        hashes = entry[i]['verification']['inclusionProof']['hashes']
        proof_log_index = entry[i]['verification']['inclusionProof']['logIndex']
        root_hash = entry[i]['verification']['inclusionProof']['rootHash']
        tree_size = entry[i]['verification']['inclusionProof']['treeSize']

        # below retrieved after decoding, see log_entry.json. I name it decode_1
        data = ast.literal_eval(base64.b64decode(entry[i]['body']).decode())
    signature = base64.b64decode(data['spec']['signature']['content'])
    # cert, like the signature, must be decoded a second time
    certificate = base64.b64decode(data['spec']['signature']['publicKey']['content'])

    # this key is literally the decoded version of the cert
    public_key = extract_public_key(certificate)

    return (signature,
            public_key,
            proof_log_index,
            tree_size,
            leaf_hash,
            hashes,
            root_hash)


def main():
    '''
    main function
    '''
    debug_flag = False

    # arg parsing
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument('-d', '--debug', help='Debug mode',
                        required=False, action='store_true')  # Default false
    parser.add_argument('-c', '--checkpoint', help='Obtain latest checkpoint\
                        from Rekor Server public instance',
                        required=False, action='store_true')
    parser.add_argument('--inclusion', help='Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567',
                        required=False, type=int)
    parser.add_argument('--artifact', help='Artifact filepath for verifying\
                        signature',
                        required=False)
    parser.add_argument('--consistency', help='Verify consistency of a given\
                        checkpoint with the latest checkpoint.',
                        action='store_true')
    parser.add_argument('--tree-id', help='Tree ID for consistency proof',
                        required=False)
    parser.add_argument('--tree-size', help='Tree size for consistency proof',
                        required=False, type=int)
    parser.add_argument('--root-hash', help='Root hash for consistency proof',
                        required=False)
    args = parser.parse_args()

    if args.debug:
        debug_flag = True
        print("enabled debug mode")

    if args.checkpoint:
        get_checkpoint()  # get latest checkpoint data from rekor

    if args.inclusion:

        if not inlclusion_arg_sane(args.inclusion, args.artifact) or debug_flag:
            print(f"bad arguments, I will use default arguments: {132216490}, file:{'artifact.md'}")
            args.inclusion = 132216490
            args.artifact = 'artifact.md'

        entry = get_log_entry(log_index=args.inclusion, debug=debug_flag)
        (signature,
         public_key,
         proof_log_index,
         tree_size,
         leaf_hash,
         hashes,
         root_hash) = signature_inclusion_proof(entry)

        verify_artifact_signature(signature, public_key, args.artifact)
        verify_inclusion(DefaultHasher, proof_log_index, tree_size, leaf_hash, hashes, root_hash)

    if args.consistency:

        if debug_flag:
            args.inclusion = 132216490
        entry = get_log_entry(log_index=args.inclusion, debug=debug_flag)

        if not consistency_arg_sane(args.tree_id, args.tree_size, args.root_hash) or debug_flag:
            print("one or multiple arguments invalid. Using default values.")
            proof_data = signature_inclusion_proof(entry)
            args.tree_size, args.root_hash = (
                args.tree_size, args.root_hash) = (
                proof_data[3], proof_data[6])  # we only need tree size and root hash

        # params: hasher, size1, size2, proof, root1, root2
        # note size2 >= size1 always, implied size 1 latest checkpoint data
        (proof_hashes,
         checkpoint_tree_size,
         checkpoint_root_hash) = get_consistency_data(args.tree_size)
        verify_consistency(DefaultHasher,
                           checkpoint_tree_size,
                           args.tree_size,
                           proof_hashes,
                           checkpoint_root_hash,
                           args.root_hash)


if __name__ == "__main__":
    main()
