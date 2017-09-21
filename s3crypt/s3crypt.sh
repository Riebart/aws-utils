#!/bin/bash

# Arg1: Hostname to send
# Arg2: Path to passphrase file
# Arg3: PGP recipient for encrypting the passphrase

if [ $# -lt 2 ]
then
    echo "Usage: s3crypt.sh <Path to folder or file> <Target Bucket> <PGP Recipient>"
    exit 1
fi

# Generate a passphrase with at least 256 bits of entropy
passphrase=$(head -c 43 /dev/urandom | base64 -w0)
passphrase_b64=$(echo -n "$passphrase" | gpg -er "$3" | base64 -w0)
echo "Base64 Passphrase: ${passphrase_b64}"

# Trim leading slash from the path
s3path=$(echo "$1" | sed 's|^/||')

size=$(du -B1 -s "$1" | cut -f1)
echo "Expected size: $size bytes"

# If the target isn't a file, then tar it up.
if [ ! -f "$1" ]
then
    tar -cvf - "$1" | \
    openssl enc -e -aes-256-cbc -k "$passphrase" | \
    pv -s $size | \
    aws s3 cp --expected-size $size --sse AES256 --metadata "symmetric-key=${passphrase_b64},symmetric-cipher=aes-256-cbc" --storage-class STANDARD - "s3://$2/${s3path}.tar.enc"
else
    cat "$1" | \
    openssl enc -e -aes-256-cbc -k "$passphrase" | \
    pv -s $size | \
    aws s3 cp --expected-size $size --sse AES256 --metadata "symmetric-key=${passphrase_b64},symmetric-cipher=aes-256-cbc" --storage-class STANDARD - "s3://$2/${s3path}.enc"
fi

echo "Base64 Passphrase: ${passphrase_b64}"
