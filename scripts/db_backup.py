#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline PostgreSQL backup/restore with streaming AES-256-GCM recipient encryption.

Use libpq PGHOST/PGPORT/PGDATABASE/PGUSER/PGPASSFILE configuration. Credentials are
never placed in command arguments or output. Restore authenticates the entire archive
before checking or changing the target database. An encrypted scratch volume is required
for its temporary decrypted dump. Database-resident wrapped data keys are included;
plaintext deployment wrapping keys and provider credentials are not.
"""
import argparse
import base64
import binascii
from contextlib import contextmanager
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAGIC = b"DABACKUP\x01"
NONCE_BYTES = 12
TAG_BYTES = 16
CHUNK = 1024 * 1024
MAX_BYTES = 32 * 1024**3  # Below GCM's per-invocation size bound; operator may lower it.


class BackupError(Exception):
    pass


def read_key(path):
    try:
        encoded = Path(path).read_bytes()
        if len(encoded) > 128:
            raise ValueError()
        key = base64.b64decode(encoded.strip(), validate=True)
        if len(key) != 32:
            raise ValueError()
        return key
    except (OSError, ValueError, binascii.Error):
        raise BackupError("Backup key must be a separate base64-encoded 32-byte recipient key") from None


def encrypt_stream(source, destination, key, max_bytes=MAX_BYTES):
    if len(key) != 32 or not 1 <= max_bytes <= MAX_BYTES:
        raise BackupError("Invalid backup encryption configuration")
    header = MAGIC + secrets.token_bytes(NONCE_BYTES)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(header[-NONCE_BYTES:])).encryptor()
    encryptor.authenticate_additional_data(header)
    destination.write(header)
    count = 0
    while chunk := source.read(CHUNK):
        count += len(chunk)
        if count > max_bytes:
            raise BackupError("Backup exceeds configured size limit")
        destination.write(encryptor.update(chunk))
    destination.write(encryptor.finalize())
    destination.write(encryptor.tag)
    return count


def decrypt_stream(source, destination, key, max_bytes=MAX_BYTES):
    if len(key) != 32 or not 1 <= max_bytes <= MAX_BYTES:
        raise BackupError("Invalid backup encryption configuration")
    source.seek(0, os.SEEK_END)
    length = source.tell()
    header_length = len(MAGIC) + NONCE_BYTES
    ciphertext_length = length - header_length - TAG_BYTES
    if ciphertext_length < 0 or ciphertext_length > max_bytes:
        raise BackupError("Invalid or oversized backup archive")
    source.seek(0)
    header = source.read(header_length)
    if header[:len(MAGIC)] != MAGIC:
        raise BackupError("Unsupported backup archive")
    source.seek(-TAG_BYTES, os.SEEK_END)
    tag = source.read(TAG_BYTES)
    source.seek(header_length)
    decryptor = Cipher(algorithms.AES(key), modes.GCM(header[-NONCE_BYTES:], tag)).decryptor()
    decryptor.authenticate_additional_data(header)
    try:
        remaining = ciphertext_length
        while remaining:
            chunk = source.read(min(CHUNK, remaining))
            if not chunk:
                raise BackupError("Truncated backup archive")
            destination.write(decryptor.update(chunk))
            remaining -= len(chunk)
        destination.write(decryptor.finalize())
    except InvalidTag:
        raise BackupError("Backup authentication failed; no database operation was started") from None
    return ciphertext_length


@contextmanager
def private_temporary(directory):
    descriptor, name = tempfile.mkstemp(prefix=".distributedai-backup-", dir=directory)
    try:
        with os.fdopen(descriptor, "w+b") as file:
            yield file, Path(name)
    finally:
        Path(name).unlink(missing_ok=True)


def _database_env():
    env = os.environ.copy()
    database = env.get("PGDATABASE", "")
    # pg_restore requires --dbname. Reject connection URIs so credentials cannot reach argv.
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_. -]{0,62}", database):
        raise BackupError("Set PGDATABASE to a database name, and use PGPASSFILE for credentials")
    env["PGAPPNAME"] = "distributedai-backup"
    return env


def backup(output, key_file, *, max_bytes=MAX_BYTES, bin_dir=None):
    output = Path(output)
    if output.exists():
        raise BackupError("Backup destination already exists")
    key = read_key(key_file)
    env = _database_env()
    executable = str(Path(bin_dir) / "pg_dump") if bin_dir else "pg_dump"
    with private_temporary(output.parent) as (encrypted, temporary):
        with subprocess.Popen([executable, "--format=custom", "--no-owner", "--no-acl"],
                              env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
            try:
                count = encrypt_stream(process.stdout, encrypted, key, max_bytes)
            except BaseException:
                process.kill()
                raise
            if process.wait() != 0:
                raise BackupError("PostgreSQL backup failed; no archive was published")
        encrypted.flush()
        os.fsync(encrypted.fileno())
        # Same-directory hard link publishes atomically without replacing any existing file.
        try:
            os.link(temporary, output)
        except FileExistsError:
            raise BackupError("Backup destination already exists") from None
    return {"payload_bytes": count, "format": "AES-256-GCM/postgresql-custom"}


def restore(archive, key_file, *, scratch_dir, confirm=False, max_bytes=MAX_BYTES, bin_dir=None):
    if not confirm:
        raise BackupError("Restore requires --confirm-restore and a new empty target database")
    key = read_key(key_file)
    with private_temporary(scratch_dir) as (plain, path):
        with Path(archive).open("rb") as encrypted:
            decrypt_stream(encrypted, plain, key, max_bytes)
        plain.flush()
        # Authentication has completed before the first target-database subprocess.
        env = _database_env()
        def binary(name):
            return str(Path(bin_dir) / name) if bin_dir else name
        check = subprocess.run([binary("psql"), "--no-psqlrc", "--tuples-only", "--no-align", "--set", "ON_ERROR_STOP=1",
            "--command", "SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema' AND c.relkind IN ('r','p','v','m','f','S');"],
            env=env, capture_output=True)
        if check.returncode or check.stdout.strip() != b"0":
            raise BackupError("Restore requires an accessible empty target database")
        result = subprocess.run([binary("pg_restore"), "--exit-on-error", "--single-transaction", "--no-owner", "--no-acl",
                                 "--dbname", env["PGDATABASE"], str(path)], env=env,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode:
            raise BackupError("PostgreSQL restore failed; its transaction was rolled back")
    return {"restored": True}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    keygen = sub.add_parser("keygen")
    keygen.add_argument("--output", required=True)
    for name in ("backup", "restore"):
        command = sub.add_parser(name)
        command.add_argument("--key-file", required=True)
        command.add_argument("--max-bytes", type=int, default=MAX_BYTES)
        command.add_argument("--pg-bin-dir")
        if name == "backup":
            command.add_argument("--output", required=True)
        else:
            command.add_argument("--archive", required=True)
            command.add_argument("--scratch-dir", required=True, help="Directory on an encrypted scratch volume")
            command.add_argument("--confirm-restore", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "keygen":
            descriptor = os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(descriptor, "wb") as file:
                file.write(base64.b64encode(secrets.token_bytes(32)) + b"\n")
            print("Recipient backup key created; store it separately from archives and application secrets.")
        elif args.command == "backup":
            backup(args.output, args.key_file, max_bytes=args.max_bytes, bin_dir=args.pg_bin_dir)
            print("Encrypted database backup completed.")
        else:
            restore(args.archive, args.key_file, scratch_dir=args.scratch_dir, confirm=args.confirm_restore,
                    max_bytes=args.max_bytes, bin_dir=args.pg_bin_dir)
            print("Database restore completed.")
    except (BackupError, OSError):
        # Avoid connection strings, filesystem secret paths and provider diagnostics in output.
        parser.exit(1, "Backup operation failed. Check the selected command, key, destination and database configuration.\n")


if __name__ == "__main__":
    main()
