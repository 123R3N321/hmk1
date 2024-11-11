import subprocess
import re

def test_artifact_correct():
    result = subprocess.run(
        ['python3', 'main.py', '--inclusion', "132216490", "--artifact", "artifact.md"],
        capture_output=True,
        text=True
    )
    output = result.stdout.split('\n')
    id_extract = output[0]
    sig_verify = output[1]
    inc_verify = output[2]

    assert len(output) == 4 # make sure we only see three messages plus a newline char
    assert re.search(r".*successful.*\b\d+$", id_extract)   #successful tree id extraction:1193050959916656506
    assert re.search(r".*\bsucceeded\b.*", sig_verify)  #artifact sig verification succeeded! -- Ren
    assert re.search(r".*\bverified\b.*", inc_verify)   #inclusion verified! --Ren

if __name__ == "__main__":
    test_artifact_correct()