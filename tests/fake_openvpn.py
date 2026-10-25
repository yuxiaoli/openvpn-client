"""Synthetic subprocess for management transport tests. Never creates a tunnel."""

import socket
import sys

args = sys.argv[1:]
index = args.index("--management")
host, port, password_file = args[index + 1 : index + 4]
with open(password_file, encoding="utf-8") as handle:
    expected = handle.read().strip()
with socket.create_connection((host, int(port)), timeout=10) as connection:
    connection.settimeout(15)
    file = connection.makefile("rwb")
    file.write(b"ENTER PASSWORD:\n")
    file.flush()
    if file.readline().strip().decode() != expected:
        raise SystemExit(1)
    file.write(b"SUCCESS: password is correct\n")
    file.flush()
    while line := file.readline():
        command = line.strip()
        if command == b"hold release":
            file.write(b">STATE:0,CONNECTED,SUCCESS,10.0.0.2,1.1.1.1,1194\n")
            file.flush()
        if command == b"signal SIGTERM":
            break
