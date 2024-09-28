'''
This is a simple use case of sigstore cosign.
The code is tested with signing a single artifact
at log index 132216490
'''


import ast
import json
import argparse
import hashlib
import re   #because Im lazy

import requests
import base64

from util import extract_public_key, verify_artifact_signature
from merkle_proof import compute_leaf_hash, DefaultHasher, verify_consistency, verify_inclusion, compute_leaf_hash, \
    RFC6962_LEAF_HASH_PREFIX


'''
fetch latest checkpoint from rekor API and print it out
'''
def get_checkpoint():
    checkpoint = requests.get('https://rekor.sigstore.dev/api/v1/log?stable=true').json()
    print(json.dumps(checkpoint, indent=4))
    print("\nabove is the latests checkpoint info, use it to cross check your artifact!")

'''
fetch the raw json of the log entry 
'''
def get_log_entry(log_index, debug = False):
    raw_entry = requests.get(f'https://rekor.sigstore.dev/api/v1/log/entries?logIndex={log_index}').json()
    if debug:
        with open("raw_log_entry.json", 'w') as f:
            json.dump(raw_entry, f)
    return raw_entry

'''
checks the sanity of the arguments
return false if not sane
'''
def inlclusion_arg_sane(log_index_arg, artifact_arg):
    return isinstance(log_index_arg, int) and log_index_arg>0 and isinstance(artifact_arg, str) and len(artifact_arg)>0

'''
checks sanity of arguments
return false if not sane
note that I am not making sure tree-id is only numerical
'''
def consistency_arg_sane(tree_id, tree_size, root_hash):
    return isinstance(tree_id, str) and len(tree_id)>0 and isinstance(tree_size, int) and tree_size>0 and isinstance(root_hash, str) and len(root_hash)>0


def get_consistency_data(current_tree_size):
    # next, we get the latest checkpoint and call verify_consistency to match against our own checkpoint
    checkpoint_response = requests.get("https://rekor.sigstore.dev/api/v1/log?stable=true")
    checkpoint_response_data = checkpoint_response.json()  # convert to json format

    checkpoint_root_hash = checkpoint_response_data['rootHash']  # str
    checkpoint_tree_id = checkpoint_response_data['treeID']  # str
    # print(f"\t\tLOOK HERE tree id: {checkpoint_tree_id}")
    checkpoint_tree_size = checkpoint_response_data['treeSize']  # int

    proof_response = requests.get(
        f"https://rekor.sigstore.dev/api/v1/log/proof?firstSize={int(checkpoint_tree_size)}&lastSize={int(current_tree_size)}&treeID={str(checkpoint_tree_id)}")
    proof_response_data = proof_response.json()
    proof_hashes = proof_response_data['hashes']

    return (proof_hashes,
        checkpoint_root_hash,
        checkpoint_tree_id,
        checkpoint_tree_size,
        checkpoint_root_hash)


'''
parses all possible data from just log entry
'''
def signature_inclusion_proof(entry):
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
            # print(f"successful tree id extraction:{tree_id}")
        else:
            print("WARNING: no tree id found")

        hashes = entry[i]['verification']['inclusionProof']['hashes']
        proof_log_index = entry[i]['verification']['inclusionProof']['logIndex']
        root_hash = entry[i]['verification']['inclusionProof']['rootHash']
        tree_size = entry[i]['verification']['inclusionProof']['treeSize']

        # below retrieved after decoding, see log_entry.json. I name it decode_1
        decode_1 = base64.b64decode(entry[i]['body']).decode()
        data = ast.literal_eval(decode_1)  # so we do not have to stare at a damn string, instead a nice dict.
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
    debug_flag = False
    data_retrieved_flag = False   #call inclusion or consistency only once to get all data needed

    #arg parsing
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument('-d', '--debug', help='Debug mode',
                        required=False, action='store_true') # Default false
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

        get_checkpoint()    #get latest checkpoint data from rekor


    if args.inclusion:

        if not inlclusion_arg_sane(args.inclusion, args.artifact) or debug_flag:
            print(f"bad arguments, I will use default arguments: {132216490}, file:{'artifact.md'}")
            args.inclusion = 132216490
            args.artifact = 'artifact.md'

        if not data_retrieved_flag:
            data_retrieved_flag = True
            entry = get_log_entry(log_index=args.inclusion, debug=debug_flag)
            signature, public_key, proof_log_index, tree_size, leaf_hash, hashes, root_hash = signature_inclusion_proof(
                entry)

        verify_artifact_signature(signature, public_key, args.artifact)
        verify_inclusion(DefaultHasher, proof_log_index, tree_size, leaf_hash, hashes, root_hash)


    if args.consistency:

        if not data_retrieved_flag:
            data_retrieved_flag = True
            if debug_flag:
                args.inclusion = 132216490
            entry = get_log_entry(log_index=args.inclusion, debug=debug_flag)

        if not consistency_arg_sane(args.tree_id, args.tree_size, args.root_hash) or debug_flag:
            print("one or multiple arguments invalid. Using default values.")
            args.tree_size, args.root_hash = (lambda t: (t[3], t[6]))(signature_inclusion_proof(entry))  # we only need tree size and root hash

        # params: hasher, size1, size2, proof, root1, root2
        # note size2 >= size1 always, implied size 1 latest checkpoint data
        proof_hashes, checkpoint_root_hash, checkpoint_tree_id, checkpoint_tree_size, checkpoint_root_hash = get_consistency_data(args.tree_size)
        verify_consistency(DefaultHasher, checkpoint_tree_size, args.tree_size, proof_hashes, checkpoint_root_hash,args.root_hash)


if __name__ == "__main__":
    main()
