import ast
import json
import argparse
import hashlib
import re   #because Im lazy
from audioop import reverse
from inspect import signature
from logging import debug

import requests
import base64

from util import extract_public_key, verify_artifact_signature
from merkle_proof import DefaultHasher, verify_consistency, verify_inclusion, compute_leaf_hash, \
    RFC6962_LEAF_HASH_PREFIX


def get_log_entry(log_index, debug=False):
    info = requests.get(f'https://rekor.sigstore.dev/api/v1/log/entries?logIndex={log_index}').json()



    # for i in info:  #info is a dict. in my case it has a single key-val pair, the key is UUID, part of it is the leaf hasg
    #     decoded = base64.b64decode(info[i]['body']).decode('utf-8')
    #     with open('log_entry.json', 'w') as file:
    #         file.write(decoded) #store the base 64 decoded log entry
    with open('raw_log_entry.json','w') as f:
        json.dump(info,f)


    # verify that log index value is sane
    pass

def extract_cert_and_sig_from_log_entry(decoded_log_entry):
    with open(decoded_log_entry, 'r') as file:
        data = json.load(file)
        sig = data['spec']['signature']['content']
        cert = data['spec']['signature']['publicKey']['content']
    print(f'\tsig is: \n\t{sig}\n')
    print(f'\tcert is: \n\t{cert}\n')   #the cert is the pubKey!
    with open('online_sig.sig', 'w') as sigfile:
        sigfile.write(sig)
    with open('online_cert.pem', 'w') as cerfile:
        cerfile.write(cert)


def get_verification_proof(log_index, debug=False):
    # verify that log index value is sane
    pass


#the functionality is also done by the custom helper step7_8() func
def inclusion(log_index, artifact_filepath, debug=False):
    # verify that log index and artifact filepath values are sane
    # extract_public_key(certificate)
    # verify_artifact_signature(signature, public_key, artifact_filepath)
    # get_verification_proof(log_index)
    # verify_inclusion(DefaultHasher, index, tree_size, leaf_hash, hashes, root_hash)
    pass

def get_latest_checkpoint(debug=False):
    pass

def consistency(prev_checkpoint, debug=False):
    # verify that prev checkpoint is not empty
    get_latest_checkpoint()
    pass

def main():
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
        checkpoint = get_latest_checkpoint(debug)
        print(json.dumps(checkpoint, indent=4))
    if args.inclusion:
        inclusion(args.inclusion, args.artifact, debug)
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

        consistency(prev_checkpoint, debug)



def fix_pem_format(pem_file_path, type = "PUBLIC KEY"):
    # Step 1: Read the key from the existing PEM file
    with open(pem_file_path, 'r') as file:
        raw_key = file.read().strip()  # Remove any leading/trailing spaces or newlines
    if "BEGIN" in raw_key:
        print("format already correct. Abort")
        return

    # Step 2: Add the PEM header and footer
    pem_header = f"-----BEGIN {type.upper()}-----"
    pem_footer = f"-----END {type.upper()}-----"

    # Step 3: Format the key into lines of 64 characters
    formatted_key = '\n'.join([raw_key[i:i+64] for i in range(0, len(raw_key), 64)])

    # Step 4: Combine the header, formatted key, and footer
    pem_formatted_key = f"{pem_header}\n{formatted_key}\n{pem_footer}"

    # Step 5: Write the corrected PEM format back into the file
    with open(pem_file_path, 'w') as file:
        file.write(pem_formatted_key)

    print(f"PEM file at '{pem_file_path}' has been corrected and saved.")


def reverse_format_pem(pem_file_path):
    with open(pem_file_path, 'r') as file:
        lines = file.readlines()

    # Remove the header and footer lines
    if len(lines) < 3:
        raise ValueError("PEM file does not contain enough lines to process")

    # Extract the key content
    key_content = ''.join(line.strip() for line in lines[1:-1])

    # Write the formatted content to the output file
    with open(pem_file_path, 'w') as file:
        file.write(key_content)

    print(f"Reformatted PEM data saved to '{pem_file_path}'")


def get_sig(filepath = 'local_sig.sig'):
    with open(filepath,'rb') as file:
        return file.read()

# requires entry["body"] output for a log entry
# returns the leaf hash according to the rfc 6962 spec
def compute_leaf_hash(body):
    entry_bytes = base64.b64decode(body)
    # create a new sha256 hash object
    h = hashlib.sha256()
    # write the leaf hash prefix
    h.update(bytes([RFC6962_LEAF_HASH_PREFIX]))
    # write the actual leaf data
    h.update(entry_bytes)
    # return the computed hash
    return h.hexdigest()


'''
Ren: this is a helper/debug func to perform step 8
note that this uses the raw log entry retrieved by previous helper funcs
'''
def step12():
    with open("raw_log_entry.json", "r") as f:
        entry = json.load(f)
    for i in entry:  # because data is a single key-val pair
        #extract some data before decoding, see raw_log_entry.json
        leaf_hash = compute_leaf_hash(entry[i]['body'])
        #hashes is the proof
        checkpoint_data = entry[i]['verification']['inclusionProof']['checkpoint']
        #we only need tree id from this part, as size and root hash are nicely given below
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

        #below retrieved after decoding, see log_entry.json. I name it decode_1
        decode_1 = base64.b64decode(entry[i]['body']).decode()
        data = ast.literal_eval(decode_1)  # so we do not have to stare at a damn string, instead a nice dict.
    signature = base64.b64decode(data['spec']['signature']['content'])
    #cert, like the signature, must be decoded a second time
    certificate = base64.b64decode(data['spec']['signature']['publicKey']['content'])

    #this key is literally the decoded version of the cert
    public_key = extract_public_key(certificate)

    # step7
    verify_artifact_signature(signature, public_key, "artifact.md")
    # get_verification_proof(132216490) # for now skip the sanity check

    #step8
    verify_inclusion(DefaultHasher, proof_log_index, tree_size, leaf_hash, hashes, root_hash, debug = True)

    #next, we get the latest checkpoint and call verify_consistency to match against our own checkpoint
    checkpoint_response = requests.get("https://rekor.sigstore.dev/api/v1/log?stable=true")
    checkpoint_response_data = checkpoint_response.json()   #convert to json format

    # with open('est.json', 'w') as testfile:   #debug code generate json
    #     json.dump(checkpoint_response_data, testfile)

    checkpoint_root_hash = checkpoint_response_data['rootHash'] #str
    checkpoint_tree_id = checkpoint_response_data['treeID'] #str
    checkpoint_tree_size = checkpoint_response_data['treeSize'] #int

    #the proof uses my own tree size against latest tree size
    proof_response = requests.get(f"https://rekor.sigstore.dev/api/v1/log/proof?firstSize={tree_size}&lastSize={checkpoint_tree_size}&treeID={checkpoint_tree_id}")
    proof_response_data = proof_response.json()

    # with open("test.json", 'w') as f: #debug file dump
    #     json.dump(proof_response_data, f)

    proof_hashes = proof_response_data['hashes']


    # params: hasher, size1, size2, proof, root1, root2
    verify_consistency(DefaultHasher, int(tree_size), int(checkpoint_tree_size), proof_hashes, root_hash,checkpoint_root_hash)





if __name__ == "__main__":
    # main()
    # get_log_entry(131489199) obsolete as we were missing cert and sig generaion
    # get_log_entry(132216490)
    # extract_cert_and_sig_from_log_entry('log_entry.json')

    # extract_public_key(base64.b64decode('LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUN6RENDQWxPZ0F3SUJBZ0lVSkdsODhoWjhSa2huUk1nT0lGV3JWOG0xY3hRd0NnWUlLb1pJemowRUF3TXcKTnpFVk1CTUdBMVVFQ2hNTWMybG5jM1J2Y21VdVpHVjJNUjR3SEFZRFZRUURFeFZ6YVdkemRHOXlaUzFwYm5SbApjbTFsWkdsaGRHVXdIaGNOTWpRd09URTVNVGMwTURJMldoY05NalF3T1RFNU1UYzFNREkyV2pBQU1Ga3dFd1lICktvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVFUXd0bEhTR2dGeXhZc0lOWVJ4UCs1MXlKbVhrbXZ4dy85OEYKN3hObHo4eUNHbXhIdDlIM0dRSUxGdmNaQnlvN2dEUndDRFpsU0pFbzVadC9OeDRjVktPQ0FYSXdnZ0Z1TUE0RwpBMVVkRHdFQi93UUVBd0lIZ0RBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGQlFjREF6QWRCZ05WSFE0RUZnUVVwQWZlCnpsVjYyUUdhZjRqbGNFMHlldkxLamJzd0h3WURWUjBqQkJnd0ZvQVUzOVBwejFZa0VaYjVxTmpwS0ZXaXhpNFkKWkQ4d0hBWURWUjBSQVFIL0JCSXdFSUVPYW5JMU9EZzNRRzU1ZFM1bFpIVXdMQVlLS3dZQkJBR0R2ekFCQVFRZQphSFIwY0hNNkx5OW5hWFJvZFdJdVkyOXRMMnh2WjJsdUwyOWhkWFJvTUM0R0Npc0dBUVFCZzc4d0FRZ0VJQXdlCmFIUjBjSE02THk5bmFYUm9kV0l1WTI5dEwyeHZaMmx1TDI5aGRYUm9NSUdLQmdvckJnRUVBZFo1QWdRQ0JId0UKZWdCNEFIWUEzVDB3YXNiSEVUSmpHUjRjbVdjM0FxSktYcmplUEszL2g0cHlnQzhwN280QUFBR1NDMTczb2dBQQpCQU1BUnpCRkFpRUF0bW9RZ0x0L05vZE1nMHpreVlkYnNJbDFjVlgxYzNkbDRBNUNvWmxJL2RvQ0lFYVFzTkorCnk2QVdqeEVXMGFrZHp6clVVSmNseWZKcy84R2VQdUxjZURIN01Bb0dDQ3FHU000OUJBTURBMmNBTUdRQ01Dc3EKdWE2RTMxemtRNHczc3dhckNXd3pCSmFDZ3IvSkRXTFRwWmw0dU9LODlGcmhnT0t1NEdjREZyOFJkL2lDSkFJdwpmRitmTUY0bmdURGpyYVNmRG80cFNLRFNCWG14aXVJY20zbnlYRVQ0cytZa2pQY0oyY3o4QWF6Tm4zTG1qOGVXCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K'))
    # verify_artifact_signature(base64.b64decode('MEMCIFz/QVJ/2595WUxl1MKhACWas3cFIIJb7cgRmFS3q1/jAh8kN8KPBxW+CfdbXJApfNZbMXg6d/+T2ZuDU3XL51CG'),
    # extract_public_key(base64.b64decode('LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUN6RENDQWxPZ0F3SUJBZ0lVSkdsODhoWjhSa2huUk1nT0lGV3JWOG0xY3hRd0NnWUlLb1pJemowRUF3TXcKTnpFVk1CTUdBMVVFQ2hNTWMybG5jM1J2Y21VdVpHVjJNUjR3SEFZRFZRUURFeFZ6YVdkemRHOXlaUzFwYm5SbApjbTFsWkdsaGRHVXdIaGNOTWpRd09URTVNVGMwTURJMldoY05NalF3T1RFNU1UYzFNREkyV2pBQU1Ga3dFd1lICktvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVFUXd0bEhTR2dGeXhZc0lOWVJ4UCs1MXlKbVhrbXZ4dy85OEYKN3hObHo4eUNHbXhIdDlIM0dRSUxGdmNaQnlvN2dEUndDRFpsU0pFbzVadC9OeDRjVktPQ0FYSXdnZ0Z1TUE0RwpBMVVkRHdFQi93UUVBd0lIZ0RBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGQlFjREF6QWRCZ05WSFE0RUZnUVVwQWZlCnpsVjYyUUdhZjRqbGNFMHlldkxLamJzd0h3WURWUjBqQkJnd0ZvQVUzOVBwejFZa0VaYjVxTmpwS0ZXaXhpNFkKWkQ4d0hBWURWUjBSQVFIL0JCSXdFSUVPYW5JMU9EZzNRRzU1ZFM1bFpIVXdMQVlLS3dZQkJBR0R2ekFCQVFRZQphSFIwY0hNNkx5OW5hWFJvZFdJdVkyOXRMMnh2WjJsdUwyOWhkWFJvTUM0R0Npc0dBUVFCZzc4d0FRZ0VJQXdlCmFIUjBjSE02THk5bmFYUm9kV0l1WTI5dEwyeHZaMmx1TDI5aGRYUm9NSUdLQmdvckJnRUVBZFo1QWdRQ0JId0UKZWdCNEFIWUEzVDB3YXNiSEVUSmpHUjRjbVdjM0FxSktYcmplUEszL2g0cHlnQzhwN280QUFBR1NDMTczb2dBQQpCQU1BUnpCRkFpRUF0bW9RZ0x0L05vZE1nMHpreVlkYnNJbDFjVlgxYzNkbDRBNUNvWmxJL2RvQ0lFYVFzTkorCnk2QVdqeEVXMGFrZHp6clVVSmNseWZKcy84R2VQdUxjZURIN01Bb0dDQ3FHU000OUJBTURBMmNBTUdRQ01Dc3EKdWE2RTMxemtRNHczc3dhckNXd3pCSmFDZ3IvSkRXTFRwWmw0dU9LODlGcmhnT0t1NEdjREZyOFJkL2lDSkFJdwpmRitmTUY0bmdURGpyYVNmRG80cFNLRFNCWG14aXVJY20zbnlYRVQ0cytZa2pQY0oyY3o4QWF6Tm4zTG1qOGVXCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K')),
    # 'artifact.md')
    step12()
