import socket
import ssl
from dnslib import DNSRecord, DNSRecord

SERVER_IP = " " #enter server's IP address

DNS_PORT     = 5053   # Plain UDP (fallback)
DNS_TLS_PORT = 8853   # DNS-over-TLS
SSL_PORT     = 8443   # General SSL control channel


# ---------------- SSL CONTROL CHANNEL ---------------- #

def ssl_connect():
    """Establish SSL control channel. Called automatically at startup."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        context = ssl._create_unverified_context()
        secure_sock = context.wrap_socket(sock, server_hostname=SERVER_IP)
        secure_sock.connect((SERVER_IP, SSL_PORT))
        secure_sock.send(b"Client connected")
        response = secure_sock.recv(1024).decode()
        print(f"[SSL]  Control channel established: {response}")
        secure_sock.close()
        return True
    except Exception as e:
        print(f"[SSL ERROR] Could not establish control channel: {e}")
        return False


# ---------------- DNS-over-TLS ---------------- #

class DoTClient:
    """
    Persistent DNS-over-TLS client.
    Keeps the TLS connection open so multiple queries can reuse it.
    Uses 2-byte length-prefixed framing (same as server).
    """

    def __init__(self):
        self.sock = None
        self.context = ssl._create_unverified_context()

    def connect(self):
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(5)
        self.sock = self.context.wrap_socket(raw, server_hostname=SERVER_IP)
        self.sock.connect((SERVER_IP, DNS_TLS_PORT))
        print(f"[DoT]  Connected to {SERVER_IP}:{DNS_TLS_PORT}")

    def query(self, domain):
        if self.sock is None:
            self.connect()

        try:
            q = DNSRecord.question(domain)
            data = q.pack()

            # Send: 2-byte length prefix + DNS query
            self.sock.sendall(len(data).to_bytes(2, "big") + data)

            # Read 2-byte length prefix
            raw_len = self._recv_exact(2)
            if not raw_len:
                print("[DoT]  No response length received")
                return

            msg_len = int.from_bytes(raw_len, "big")
            response_data = self._recv_exact(msg_len)

            if response_data:
                print("\n[DoT]  DNS Response:")
                print(DNSRecord.parse(response_data))
            else:
                print("[DoT]  Incomplete response")

        except Exception as e:
            print(f"[DoT ERROR] {e}")
            # Reconnect on next query
            self.sock = None

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None


# ---------------- PLAIN UDP DNS (fallback) ---------------- #

def dns_query_udp(domain):
    """Fallback: plain UDP DNS query (no encryption)."""
    q = DNSRecord.question(domain)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    sock.sendto(q.pack(), (SERVER_IP, DNS_PORT))
    try:
        data, _ = sock.recvfrom(512)
        print("\n[UDP DNS] Response:")
        print(DNSRecord.parse(data))
    except Exception as e:
        print(f"[UDP DNS] No response: {e}")
    finally:
        sock.close()


# ---------------- MAIN ---------------- #

if __name__ == "__main__":
    # Auto-establish SSL control channel on startup
    print("=" * 45)
    print("  DNS-over-TLS Client")
    print("=" * 45)
    ssl_connect()

    # Create persistent DoT client
    dot = DoTClient()
    try:
        dot.connect()
    except Exception as e:
        print(f"[DoT]  Could not connect: {e}")

    while True:
        print("\n1. DNS Query (over TLS)")
        print("2. DNS Query (plain UDP fallback)")
        print("3. Exit")
        ch = input("Choice: ").strip()

        if ch == "1":
            d = input("Domain: ").strip()
            dot.query(d)

        elif ch == "2":
            d = input("Domain: ").strip()
            dns_query_udp(d)

        elif ch == "3":
            dot.close()
            break
