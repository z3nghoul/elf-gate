# Raw DNS client used as "the system resolver talking to its upstream": dns_query.py <server> <name>
import socket, sys
server, name = sys.argv[1], sys.argv[2]
q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00\x00\x01\x00\x01"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(q, (server, 53))
try:
    r, _ = s.recvfrom(512); print(".".join(str(b) for b in r[-4:]))
except Exception as e:
    print("FAIL")
