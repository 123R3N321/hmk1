# This is homework1 of CS-GY/UY 3943/9223 SUpply Chain Secrity

## how to use:
commands:
- python3 main.py -c
- python3 main.py --inclusion artifact.md 
  - (the last command can be changed to anything you sign)
- python3 main.py --consistency

## notes
The point of this homework is the know-how of cosign tools, i particular the rekor APIs
- the "security" is implemented as a merkle tree, and in this homework I compare two nodes in the tree:
the latest checkpoint provided by Rekor that is just simply literally the latest checkpoint
and the checkpoint of my own signed artifact which is retrievable via
api call using the log index generated when I signed the artifact.

## reference materials:
- Template Code: https://github.com/mayank-ramnani/python-rekor-monitor-template
- Rekor API Spec: https://www.sigstore.dev/swagger/#/tlog/getLogInfo