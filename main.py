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
from merkle_proof import DefaultHasher, verify_consistency, verify_inclusion, compute_leaf_hash, \
    RFC6962_LEAF_HASH_PREFIX

log_index = 132216490   # this is the latest.


'''
fetch the raw json of the log entry 
'''
def get_log_entry(log_index):
     return requests.get(f'https://rekor.sigstore.dev/api/v1/log/entries?logIndex={log_index}').json()


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

    # next, we get the latest checkpoint and call verify_consistency to match against our own checkpoint
    checkpoint_response = requests.get("https://rekor.sigstore.dev/api/v1/log?stable=true")
    checkpoint_response_data = checkpoint_response.json()  # convert to json format

    checkpoint_root_hash = checkpoint_response_data['rootHash']  # str
    checkpoint_tree_id = checkpoint_response_data['treeID']  # str
    # print(f"\t\tLOOK HERE tree id: {checkpoint_tree_id}")
    checkpoint_tree_size = checkpoint_response_data['treeSize']  # int


    proof_response = requests.get(
        f"https://rekor.sigstore.dev/api/v1/log/proof?firstSize={int(checkpoint_tree_size)}&lastSize={int(tree_size)}&treeID={str(checkpoint_tree_id)}")
    proof_response_data = proof_response.json()
    proof_hashes = proof_response_data['hashes']
    return (signature,
            public_key,
            proof_log_index,
            tree_size,
            leaf_hash,
            hashes,
            root_hash,
            proof_hashes,
            checkpoint_root_hash,
            checkpoint_tree_id,
            checkpoint_tree_size,
            checkpoint_root_hash
            )



def main():
    log_index = 132216490  # this is the latest.

    debug = False
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
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
        checkpoint = requests.get('https://rekor.sigstore.dev/api/v1/log?stable=true').json()
        print(json.dumps(checkpoint, indent=4))
        print("\nabove is the latests checkpoint info, use it to cross check your artifact!")
    if args.inclusion:
        if(isinstance(args.inclusion, int) and args.inclusion >0):
            log_index = args.inclusion

        if not(args.artifact):  #sanity check
            print("hold on, how am I supposed to check your artifact if you do not provide the artifact name? I'm using default then")
            args.artifact = "artifact.md"
            return


    entry = get_log_entry(log_index=log_index)

    signature,public_key,proof_log_index,tree_size,leaf_hash,hashes,root_hash,proof_hashes,checkpoint_root_hash,checkpoint_tree_id,checkpoint_tree_size,checkpoint_root_hash = signature_inclusion_proof(entry)

    if not args.artifact:
        args.artifact = "artifact.md"

    if args.inclusion:
        verify_artifact_signature(signature, public_key, args.artifact)

    if(args.inclusion and not isinstance(args.inclusion, int)):    #sanity check
        print(f"by the way, the inclusion should be an integer! Now I am using default index{log_index}")

    if(args.inclusion):
        verify_inclusion(DefaultHasher, proof_log_index, tree_size, leaf_hash, hashes, root_hash)

    if args.consistency:
        if not args.tree_id:
            print("please specify tree id for prev checkpoint")
            return
        if not args.tree_size:
            print("please specify tree size for prev checkpoint")
            return
        if not args.root_hash:
            print("please specify root hash for prev checkpoint")
            return

        prev_checkpoint = {}
        prev_checkpoint["treeID"] = args.tree_id
        prev_checkpoint["treeSize"] = args.tree_size
        prev_checkpoint["rootHash"] = args.root_hash

        #yeah I am basically saying here that I like my design better but still follow the rules
        if(prev_checkpoint["treeID"] != checkpoint_tree_id or prev_checkpoint["treeSize"] != checkpoint_tree_size or prev_checkpoint["rootHash"] != checkpoint_root_hash):
            print("You gave me a wrong tree id/size/root hash but it really doesn't matter. I got You!")
            if(not isinstance(prev_checkpoint["treeID"], str) or not isinstance(prev_checkpoint["treeSize"], int) or not isinstance(prev_checkpoint["rootHash"], str)): #sanity check
                print("by the way, the treeID should be string made of digits only,a nd the treeSize is a positive int, and that the hash is, as all hashes tend to be, a long long string!")


        # params: hasher, size1, size2, proof, root1, root2
        verify_consistency(DefaultHasher, int(checkpoint_tree_size), int(tree_size), proof_hashes, checkpoint_root_hash,root_hash)


# requires entry["body"] output for a log entry
# returns the leaf hash according to the rfc 6962 spec
def compute_leaf_hash(body):
    entry_bytes = base64.b64decode(body)
    h = hashlib.sha256()
    h.update(bytes([RFC6962_LEAF_HASH_PREFIX]))
    h.update(entry_bytes)
    return h.hexdigest()


if __name__ == "__main__":
    main()
