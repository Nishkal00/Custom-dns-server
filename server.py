import socketserver
import socket
import ssl
import threading
import time
from dnslib import *

DNS_PORT = 5053       # Plain UDP DNS (kept for compatibility)
DNS_TLS_PORT = 8853   # DNS-over-TLS
SSL_PORT = 8443       # General SSL channel
TTL = 300

UPSTREAM_DNS = ("8.8.8.8", 53)

RECORDS = {
    "example.com.": "127.0.0.1",
    "amazon.com.": "192.168.1.10",
    "reddit.com.": "192.168.1.11",
}


# ---------------- DNS LOGIC ---------------- #

def forward_dns(data):
    """Forward query to upstream DNS (8.8.8.8) if not found locally."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.sendto(data, UPSTREAM_DNS)
        response, _ = sock.recvfrom(512)
        return response
    except Exception as e:
        print(f"[FORWARD ERROR] {e}")
        return None


def dns_response(data):
    """Build a DNS response: local resolution or recursive forward."""
    start_time = time.time()

    try:
        if len(data) > 512:
            print("[DNS] Packet too large, dropping")
            return None

        request = DNSRecord.parse(data)
    except Exception as e:
        print(f"[DNS] Invalid packet: {e}")
        return None

    qname = str(request.q.qname)
    qtype = QTYPE[request.q.qtype]

    reply = DNSRecord(
        DNSHeader(id=request.header.id, qr=1, aa=1, ra=1),
        q=request.q
    )

    if qtype != "A":
        reply.header.rcode = RCODE.NOTIMP
        return reply.pack()

    if qname in RECORDS:
        ip = RECORDS[qname]
        reply.add_answer(
            RR(
                rname=request.q.qname,
                rtype=QTYPE.A,
                rclass=1,
                ttl=TTL,
                rdata=A(ip)
            )
        )
        print(f"[LOCAL]   {qname} -> {ip}")
    else:
        print(f"[FORWARD] {qname}")
        forwarded = forward_dns(data)
        if forwarded:
            elapsed = (time.time() - start_time) * 1000
            print(f"[FORWARD] Response time: {elapsed:.2f} ms")
            return forwarded
        else:
            reply.header.rcode = RCODE.SERVFAIL
            return reply.pack()

    elapsed = (time.time() - start_time) * 1000
    print(f"[LOCAL]   Response time: {elapsed:.2f} ms")
    return reply.pack()


# Plain UDP DNS handler
class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        response = dns_response(data)
        if response:
            sock.sendto(response, self.client_address)


def start_dns():
    server = socketserver.ThreadingUDPServer(("", DNS_PORT), DNSHandler)
    print(f"[DNS]     UDP server running on port {DNS_PORT}")
    server.serve_forever()


# ---------------- DNS-over-TLS LOGIC ---------------- #

def handle_dns_tls(conn, addr):
    """
    Handle a DNS-over-TLS connection.
    Protocol: 2-byte length prefix followed by the DNS query bytes.
    """
    print(f"[DoT]     Connection from {addr}")
    try:
        conn.settimeout(10)
        while True:
            # Read 2-byte length prefix
            raw_len = conn.recv(2)
            if not raw_len or len(raw_len) < 2:
                break

            msg_len = int.from_bytes(raw_len, "big")
            data = b""

            while len(data) < msg_len:
                chunk = conn.recv(msg_len - len(data))
                if not chunk:
                    break
                data += chunk

            if len(data) < msg_len:
                break

            response = dns_response(data)

            if response:
                # Prefix response with 2-byte length
                conn.sendall(len(response).to_bytes(2, "big") + response)

    except Exception as e:
        print(f"[DoT ERROR] {addr}: {e}")
    finally:
        conn.close()


def start_dns_tls():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", DNS_TLS_PORT))
    sock.listen(10)

    print(f"[DoT]     DNS-over-TLS running on port {DNS_TLS_PORT}")

    while True:
        try:
            client, addr = sock.accept()
            secure_conn = context.wrap_socket(client, server_side=True)
            threading.Thread(
                target=handle_dns_tls,
                args=(secure_conn, addr),
                daemon=True
            ).start()
        except ssl.SSLError as e:
            print(f"[DoT SSL ERROR] {e}")
        except Exception as e:
            print(f"[DoT ACCEPT ERROR] {e}")


# ---------------- SSL CONTROL CHANNEL ---------------- #

def handle_ssl(conn, addr):
    print(f"[SSL]     Connected: {addr}")
    try:
        conn.settimeout(5)
        data = conn.recv(1024).decode()
        print(f"[SSL]     Received: {data}")
        conn.send(b"Secure channel active")
    except ssl.SSLError as e:
        print(f"[SSL HANDSHAKE ERROR] {addr}: {e}")
    except Exception as e:
        print(f"[SSL ERROR] {addr}: {e}")
    finally:
        conn.close()


def start_ssl():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", SSL_PORT))
    sock.listen(5)

    print(f"[SSL]     Control channel running on port {SSL_PORT}")

    while True:
        try:
            client, addr = sock.accept()
            secure_conn = context.wrap_socket(client, server_side=True)
            threading.Thread(
                target=handle_ssl,
                args=(secure_conn, addr),
                daemon=True
            ).start()
        except ssl.SSLError as e:
            print(f"[SSL HANDSHAKE ERROR] {e}")
        except Exception as e:
            print(f"[SSL ACCEPT ERROR] {e}")


# ---------------- MAIN ---------------- #

if __name__ == "__main__":
    threading.Thread(target=start_dns,     daemon=True).start()
    threading.Thread(target=start_dns_tls, daemon=True).start()
    threading.Thread(target=start_ssl,     daemon=True).start()

    print("Server running (UDP DNS + DNS-over-TLS + SSL)...\n")

    while True:
        time.sleep(1)
