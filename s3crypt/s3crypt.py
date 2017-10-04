#!/usr/bin/env python
"""
Simplify putting and retrieving encrypted contents from S3 by encoding PGP protected passphrase
information and symmetric crypto information into S3 object metadata.
"""

import os
import base64
import sys
import argparse
import subprocess
import tempfile
import boto3


def humansize_to_bytes(val):
    """
    Convert human-readable numeric values into pure-numeric values. Supports a range of suffixes
    but assumes most of them map to decimal (1000-based) bases with support for a couple binary
    suffixes.
    """
    suffixes = {
        "k": 1000,
        "m": 1000**2,
        "g": 1000**3,
        "t": 1000**4,
        "kb": 1000,
        "mb": 1000**2,
        "gb": 1000**3,
        "tb": 1000**4,
        "Kb": 1000,
        "Mb": 1000**2,
        "Gb": 1000**3,
        "Tb": 1000**4,
        "kB": 1000,
        "KB": 1000,
        "MB": 1000**2,
        "GB": 1000**3,
        "TB": 1000**4,
        "K": 1024,
        "M": 1024**2,
        "G": 1024**3,
        "T": 1024**4,
        "kiB": 1024,
        "MiB": 1024**2,
        "GiB": 1024**3,
        "TiB": 1024**4
    }
    for suffix, value in suffixes.iteritems():
        if val.endswith(suffix):
            return int(float(val[:-len(suffix)]) * value)
    return int(float(val))


def __encrypt(pargs):
    """
    Perform encryption and upload of input data. Tars up directories if given them as a source.
    """
    if pargs.source is None and pargs.key is None:
        sys.stderr.write(
            "Either the source (a filesystem location) or the S3 key must be specified."
        )
        exit(1)

    isdir = False
    if pargs.source is not None and pargs.key is None:
        keypath = pargs.source
        if keypath[0] == '/':
            keypath = keypath[1:]
        if keypath[-1] == '/':
            keypath = keypath[:-1]

        if os.path.isfile(pargs.source):
            pargs.key = keypath + ".gpgenc"
        elif os.path.isdir(pargs.source):
            isdir = True
            pargs.key = keypath + ".tar.gpgenc"

    # Sufficient entropy for a 256 bit key
    passphrase = base64.b64encode(os.urandom(32))
    gpgproc = subprocess.Popen(
        ("gpg", "-er", pargs.pgp_recipient),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE)
    gpgresult, _ = gpgproc.communicate(input=passphrase)
    encrypted_passphrase = base64.b64encode(gpgresult)
    print "Base64 GPG-protected passphrase:", encrypted_passphrase

    # Get the exected size of the filesystem source
    if pargs.source is not None and pargs.expected_size is None:
        pargs.expected_size = int(
            subprocess.check_output(("du", "-sB1", pargs.source)).split("\t")[
                0])

    # If the target is a directory, start by tarring that up
    if isdir:
        inproc = subprocess.Popen(
            ("tar", "-cvf", "-", pargs.source), stdout=subprocess.PIPE)
        inpipe = inproc.stdout
    else:
        inproc = None
        inpipe = sys.stdin

    cryptproc = subprocess.Popen(
        ("openssl", "enc", "-e", "-%s" % pargs.symmetric_algorithm, "-k",
         passphrase),
        stdin=inpipe,
        stdout=subprocess.PIPE)

    s3proc = subprocess.Popen(
        ("aws", "s3", "cp", "--sse", "AES256") + \
        (
            () if pargs.expected_size is None
            else ("--expected-size", str(humansize_to_bytes(pargs.expected_size)))) + \
        (
            "--metadata",
            "symmetric-key=%s,symmetric-cipher=%s" % (encrypted_passphrase, pargs.symmetric_algorithm),
            "--storage-class", "STANDARD",
            "-", "s3://%s/%s" % (pargs.bucket, pargs.key)),
        stdin=cryptproc.stdout
    )

    s3proc.communicate()


def __decrypt(pargs):
    """
    Perform decryption and fetching of data from S3. Untar tarballs if set.
    """
    s3 = boto3.client("s3")

    headers = s3.head_object(Bucket=pargs.bucket, Key=pargs.key)
    if "Metadata" not in headers:
        sys.stderr.write(
            "Unable to find crypto headers in object metadata. Aborting.")
        exit(2)

    symmetric_algorithm = headers["Metadata"].get("symmetric-cipher", None)
    symmetric_key_opaque = headers["Metadata"].get("symmetric-key", None)

    if symmetric_algorithm is None or symmetric_key_opaque is None:
        sys.stderr.write("Unable to find cipher or key in metadata headers: %s"
                         % str(headers.keys()))
        exit(3)

    # To free stdin in our TTY up for gpg, write the encrypted goop to a temporary file for gpg
    # to read and decrypt. Since the contents are encrypted, we don't need to be too careful about
    # cleaning up after ourselves. This depends on a writable TMP location.
    tfile = tempfile.NamedTemporaryFile(mode="w+b")
    tfile.write(base64.b64decode(symmetric_key_opaque))
    tfile.flush()
    symmetric_key = subprocess.check_output(("gpg", "-d", tfile.name))
    tfile.close()

    outfd = None
    if pargs.destination is None:
        outfd = sys.stdout
    elif pargs.untar:
        outfd = subprocess.PIPE
    else:
        outfd = open(pargs.destination, "wb")

    s3proc = subprocess.Popen(
        ("aws", "s3", "cp", "s3://%s/%s" % (pargs.bucket, pargs.key), "-"),
        stdout=subprocess.PIPE)

    cryptproc = subprocess.Popen(
        ("openssl", "enc", "-d", "-%s" % symmetric_algorithm, "-k",
         symmetric_key),
        stdin=s3proc.stdout,
        stdout=outfd)

    if pargs.destination is None:
        cryptproc.communicate()
    elif pargs.untar:
        untarproc = subprocess.Popen(
            ("tar", "-xf", "-"), cwd=pargs.destination, stdin=cryptproc.stdout)
    else:
        outfd.flush()
        outfd.close()


def __main():
    parser = argparse.ArgumentParser(
        description="""Accepts either a path or from stdin, and puts the resulting content
        into S3 encrypted with symmetric crypto, embeddeding the crypto keys in the object
        metadata encrypted with a PGP key.""")
    subparsers = parser.add_subparsers(dest="command")
    encrypt = subparsers.add_parser("encrypt")
    encrypt.add_argument(
        "--pgp-recipient",
        required=True,
        help="""Email address, key ID, or other indicator of the PGP public key to use for
        encrypting the symmetric key component""")
    encrypt.add_argument(
        "--source",
        required=False,
        default=None,
        help="""If specified, points to the local directory or file to send to S3. If
        omitted, stdin is assumed to be the source.""")
    encrypt.add_argument(
        "--s3-bucket",
        required=True,
        help="""Bucket name for the output object.""")
    encrypt.add_argument(
        "--s3-key",
        required=False,
        default=None,
        help="""Key name for the output object. Required if stdin is the source, and option
        if the source is a filesystem location.""")
    encrypt.add_argument(
        "--expected-size",
        required=False,
        default=None,
        help="""The expected size of the input. For filesystem sources this is determined
        automatically if this is not given, but for stdin sources, this should be
        specified. This is passed directly to the option of the same name in the AWS CLI s3
        cp command. Without this command, uploads are limited to about 100GiB."""
    )
    encrypt.add_argument(
        "--symmetric-algorithm",
        required=False,
        default="aes-256-cbc",
        help="""Cipher to pass to OpenSSL for encryption. Must be supported by OpenSSL."""
    )
    decrypt = subparsers.add_parser("decrypt")
    decrypt.add_argument(
        "--bucket",
        required=True,
        help="""Bucket name for the input object.""")
    decrypt.add_argument(
        "--key", required=True, help="""Key name for the input object.""")
    decrypt.add_argument(
        "--destination",
        required=False,
        help="""Filesystem location to place the resulting stream. If omitted it defaults
        to stdout.""")
    decrypt.add_argument(
        "--untar",
        required=False,
        default=False,
        action="store_true",
        help="""Attempt to untar the decrypted content. NO checks are made to ensure that the output
        data is a tarfile, and if it isn't this will quickly fail.""")
    pargs = parser.parse_args()

    if pargs.command == "encrypt":
        return __encrypt(pargs)
    elif pargs.command == "decrypt":
        return __decrypt(pargs)


if __name__ == "__main__":
    __main()
