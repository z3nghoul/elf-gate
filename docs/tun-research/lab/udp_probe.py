import socket, sys, time
host, port, n, size = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(0.3)
rtts, lost, peer = [], 0, ""
for i in range(n):
    payload = (b"%05d" % i) + b"x" * (size - 5)
    t = time.perf_counter(); s.sendto(payload, (host, port))
    try:
        data, _ = s.recvfrom(65535); rtts.append((time.perf_counter() - t) * 1000)
        peer = data.split(b"|")[0].decode(); assert data.endswith(payload)
    except socket.timeout: lost += 1
    time.sleep(0.01)
rtts.sort()
print(f"udp size={size} sent={n} lost={lost} {peer}" + (f" rtt_ms p50={rtts[len(rtts)//2]:.2f} max={rtts[-1]:.2f}" if rtts else ""))
