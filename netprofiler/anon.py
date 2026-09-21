"""Addresses and ports are never stored. While a packet or flow record is
being parsed they are hashed with a per-process random salt; only the
digests are kept, for flow identity, endpoint counting and matching the
profiler's own sockets. The salt is not persisted, so digests cannot be
compared across runs or reversed."""

from __future__ import annotations

import hashlib
import os

_SALT = os.urandom(16)


def flow_id(proto: int, local_port: int, remote_ip: str, remote_port: int) -> str:
    return hashlib.blake2b(f"{proto}|{local_port}|{remote_ip}|{remote_port}".encode(), key=_SALT, digest_size=8).hexdigest()


def endpoint_id(proto: int, remote_ip: str, remote_port: int) -> str:
    return hashlib.blake2b(f"{proto}|{remote_ip}|{remote_port}".encode(), key=_SALT, digest_size=8).hexdigest()


def host_id(remote_ip: str) -> str:
    return hashlib.blake2b(remote_ip.encode(), key=_SALT, digest_size=8).hexdigest()
