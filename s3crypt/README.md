# s3crypt.py

This isn't a unique tool, but it is my take on the client-encrypted S3 upload helper. This tool ingests data from the filesystem (a file or directory, with the latter being automatically tarred) or stdin, uses PGP to encrypt the symmetric key (randomly generated on each call with 32 bytes from `urandom()`) and store it as metadata with the S3 object. It then puts the encrypted stream into an S3 object.

The bash script (`s3crypt.sh`) is really only meant for example purposes, and implements a subset of the functionality of the Python script.

## Requirements

Python, boto3, the AWS CLI, the OpenSSL cli command, the CLI `tar` command, and the `gpg` command with the necessary public and/or private keys. Private keys are only needed for decrypting, so you can still push objects into S3 with only the recipient's public key.

## Usage

**Note: None of the buckets, PGP keys, or secret material is real. These are all examples.**

Example: Saving a Docker image (potentially containing sensitive information) to S3 with `docker save`.

```bash
$ docker save riebart/keybase:latest | s3crypt.py encrypt --s3-bucket docker-images --s3-key riebart/keybase:latest --pgp-recipient john@example.com --estimated-size 1G
```

Example: Retrieving the same Docker image from S3, decrypting it, and loading it into Docker.

```bash
$ s3crypt.py decrypt --s3-bucket docker-images --s3-key riebart/keybase:latest | docker load

You need a passphrase to unlock the secret key for
user: "John Doe <john@example.com>"
4096-bit RSA key, ID 15128DF3, created 2010-08-27 (main key ID D2D744AA)

gpg: encrypted with 4096-bit RSA key, ID 15128DF3, created 2010-08-27
      "John Doe <john@example.com>"
...
```

Example: Saving secrets to S3 encrypted with PGP, essentially turning S3 into a password vault.

```bash
$ echo "Riebart
UL!6s*d7aj/<P-(IE})9?&v^KA;%n4pwH#NX|$~\By=eV80+WoO>kcTi,mt[Jrq" | s3crypt.py encrypt --s3-bucket passwords --s3-key github.com --pgp-recipient john@example.com

$ s3crypt.py decrypt --s3-bucket passwords --s3-key github.com

You need a passphrase to unlock the secret key for
user: "John Doe <john@example.com>"
4096-bit RSA key, ID 15128DF3, created 2010-08-27 (main key ID D2D744AA)

gpg: encrypted with 4096-bit RSA key, ID 15128DF3, created 2010-08-27
      "John Doe <john@example.com>"
...
```
