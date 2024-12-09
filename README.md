[![Continuous Integration](https://github.com/123R3N321/hmk1/actions/workflows/ci.yml/badge.svg)](https://github.com/123R3N321/hmk1/actions/workflows/ci.yml)
[![Continuous Deployment (Build and Release)](https://github.com/123R3N321/hmk1/actions/workflows/cd.yml/badge.svg)](https://github.com/123R3N321/hmk1/actions/workflows/cd.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/123R3N321/hmk1/badge)](https://scorecard.dev/viewer/?uri=github.com/123R3N321/hmk1)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/9790/badge)](https://www.bestpractices.dev/projects/9790)
# This is homework1 of CS-GY/UY 3943/9223 SUpply Chain Secrity

## set-up:
This entire project is based on the sigstore [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) tools
on linux:
```bash
curl -O -L "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64"
sudo mv cosign-linux-amd64 /usr/local/bin/cosign
sudo chmod +x /usr/local/bin/cosign
```
If you have ``go`` or ``homebrew`` it would be easier.
## Signing an artifact:
1. Sign an artifact using cosign tool with your identity using:
```bash
    cosign sign-blob <file> --bundle cosign.bundle
  ```
You can also refer to the official [cosign tutorial](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/)

## After signing an artifact:
commands:
```bash
python3 main.py -c
python3 main.py --inclusion <artifact> 
  # (the last argument can be changed to anything you signed)
python3 main.py --consistency
```
## Important notes:

- This repo runs a [Trufflehog](https://github.com/trufflesecurity/trufflehog) 
    command to scan each latest commit attempt to prevent secret leak,
    however, the local repo on linux environment resulted in likely non-functional
    pre-commit config. The Docker image of Trufflehog does not support laetst one-
    commit scan. For Mac environment, modify ``pre-commit-config.yaml``, line 7, to:
    ```yaml
    entry: bash -c 'trufflehog git file://. --since-commit HEAD --no-verification --fail --max-depth=1'
    ```

## notes
The point of this homework is the know-how of cosign tools, i particular the rekor APIs
- the "security" is implemented as a merkle tree, and in this homework I compare two nodes in the tree:
the latest checkpoint provided by Rekor that is just simply literally the latest checkpoint
and the checkpoint of my own signed artifact which is retrievable via
api call using the log index generated when I signed the artifact.

- somehow against my simple understanding of the merkle tree implementation, the "treeSize" filed goes backward:
If you check the log index 1 on Rekor, the tree size is huge (4163431) while by the point I did this homework
and signed a dummy, the size is only 1110000+ ~ish, I wonder what happens when number
reaches 0.

- prof explained in class that this implementation is lighter-weight than actual blockchain but I don't quite see why or how.

- api call for latest checkpoint entry, do NOT specify stable=True


##notes on creating another bundle for the wheel, and verify it:
raw command for this project:
```bash
cosign attest-blob dist/hmk1-0.1.5-py3-none-any.whl --predicate cyclonedx-sbom.json --bundle sbom.bundle --type cyclonedx
cosign verify-blob-attestation --bundle sbom.bundle dist/hmk1-0.1.5-py3-none-any.whl --certificate-identity jr5887@nyu.edu --certificate-oidc-issuer https://token.actions.githubusercontent.com --type cyclonedx --check-claims
```

## reference materials:
- [Template Code from class TA](https://github.com/mayank-ramnani/python-rekor-monitor-template)
- [Rekor API Spec](https://www.sigstore.dev/swagger/#/tlog/getLogInfo)