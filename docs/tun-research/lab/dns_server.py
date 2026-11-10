# Tiny DNS responder for the lab: every A query -> 198.51.100.2; logs the asking address.
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((sys.argv[1], 53))
log = open(sys.argv[2], "a", buffering=1)
while True:
    q, peer = s.recvfrom(512)
    log.write(f"query from {peer[0]}\n")
    i = 12
    while q[i] != 0: i += q[i] + 1
    qend = i + 5                       # name + type + class
    resp = q[:2] + b"\x81\x80" + q[4:6] + b"\x00\x01\x00\x00\x00\x00" + q[12:qend]
    resp += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes([198, 51, 100, 2])
    s.sendto(resp, peer)
