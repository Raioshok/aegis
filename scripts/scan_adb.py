import socket
import concurrent.futures

subnet = "172.17.240."
active_ips = []

def check_ip(i):
    ip = f"{subnet}{i}"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.3)
    # Check port 5555 (ADB)
    res = s.connect_ex((ip, 5555))
    s.close()
    if res == 0:
        return ip
    return None

with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
    futs = [ex.submit(check_ip, i) for i in range(2, 255)]
    for f in concurrent.futures.as_completed(futs):
        r = f.result()
        if r:
            active_ips.append(r)

print("Found ADB endpoints:", active_ips)
