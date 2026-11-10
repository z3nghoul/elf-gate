# Tiny DNS responder for the lab: every A query -> ANSWER (default 198.51.100.2); logs the asking address.
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((sys.argv[1], 53))
log = open(sys.argv[2], "a", buffering=1)
ANSWER = [int(x) for x in (sys.argv[3] if len(sys.argv) > 3 else "198.51.100.2").split(".")]
while True:
    q, peer = s.recvfrom(512)
    name = []
    j = 12
    while q[j] != 0:
        name.append(q[j + 1:j + 1 + q[j]].decode()); j += q[j] + 1
    log.write(f"query {'.'.join(name)} from {peer[0]}\n")
    i = 12
    while q[i] != 0: i += q[i] + 1
    qend = i + 5                       # name + type + class
    resp = q[:2] + b"\x81\x80" + q[4:6] + b"\x00\x01\x00\x00\x00\x00" + q[12:qend]
    resp += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes(ANSWER)
    s.sendto(resp, peer)
