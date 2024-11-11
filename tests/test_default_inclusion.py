import subprocess
import re

def default_behavior():
    result = subprocess.run(
        ['python3', 'main.py', '--inclusion', "132216490", "--artifact"],
        capture_output=True,
        text=True
    )
    output = result.stdout.split('\n')
    default = output[0]
    id_extract = output[1]
    sig_verify = output[2]
    inc_verify = output[3]

    assert len(output) == 5 # make sure we only see four messages plus a newline char
    assert re.search(r".*\bdefault\b.*", default)   #successful tree id extraction:1193050959916656506
    assert re.search(r".*successful.*\b\d+$", id_extract)   #successful tree id extraction:1193050959916656506
    assert re.search(r".*\bsucceeded\b.*", sig_verify)  #artifact sig verification succeeded! -- Ren
    assert re.search(r".*\bverified\b.*", inc_verify)   #inclusion verified! --Ren

if __name__ == "__main__":
    default_behavior()