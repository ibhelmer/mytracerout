from scapy.all import IP, ICMP, sr1
import socket

def scapy_traceroute(target, max_hops=30):
    print(f"Traceroute to {target}:")
    for ttl in range(1, max_hops + 1):
        pkt = IP(dst=target, ttl=ttl) / ICMP()
        reply = sr1(pkt, verbose=0, timeout=2)

        if reply is None:
            print(f"{ttl} * * * Request timed out.")
        elif reply.type == 11:  # Time-to-live exceeded
            host = socket.getnameinfo((reply.src,0),0)
            if host[0]==reply.src:
                hostname=""
            else:
                hostname=host[0]
            print(f"{ttl} {reply.src} {hostname} ")


        elif reply.type == 0:  # Echo reply (means we reached the destination)
            host = socket.getnameinfo((reply.src,0),0)
            if host[0]==reply.src:
                hostname=""
            else:
                hostname=host[0]
            print(f"{ttl} {reply.src} {hostname} - Reached destination.")
            break
    else:
        print("Traceroute failed or maximum hops reached.")

if __name__ == "__main__":
    target_ip = input("Enter the targets host name or IP address: ")
    scapy_traceroute(target_ip)
