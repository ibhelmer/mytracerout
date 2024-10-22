from scapy.all import IP, ICMP, sr1

def scapy_traceroute(target, max_hops=30):
    print(f"Traceroute to {target}:")
    for ttl in range(1, max_hops + 1):
        pkt = IP(dst=target, ttl=ttl) / ICMP()
        reply = sr1(pkt, verbose=0, timeout=1)

        if reply is None:
            print(f"{ttl} * * * Request timed out.")
        elif reply.type == 11:  # Time-to-live exceeded
            print(f"{ttl} {reply.src}")
        elif reply.type == 0:  # Echo reply (means we reached the destination)
            print(f"{ttl} {reply.src} - Reached destination.")
            break
    else:
        print("Traceroute failed or maximum hops reached.")

if __name__ == "__main__":
    target_ip = input("Enter the target IP address: ")
    scapy_traceroute(target_ip)
