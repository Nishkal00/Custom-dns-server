from OpenSSL import crypto

SERVER_IP = "192.168.56.1"  # Change this to your server machine's IP

key = crypto.PKey()
key.generate_key(crypto.TYPE_RSA, 2048)

cert = crypto.X509()
cert.get_subject().CN = SERVER_IP
cert.set_serial_number(1000)
cert.gmtime_adj_notBefore(0)
cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
cert.set_issuer(cert.get_subject())
cert.set_pubkey(key)

# Subject Alternative Name — required for modern TLS to accept an IP-based cert
cert.add_extensions([
    crypto.X509Extension(
        b"subjectAltName",
        False,
        f"IP:{SERVER_IP}".encode()
    )
])

cert.sign(key, 'sha256')

with open("cert.pem", "wb") as f:
    f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

with open("key.pem", "wb") as f:
    f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

print(f"cert.pem and key.pem generated for IP: {SERVER_IP}")
