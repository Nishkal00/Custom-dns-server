# Custom DNS Server 

This project implements a lightweight DNS server using Python socket
programming. It supports both traditional UDP-based DNS queries and
secure DNS-over-TLS (DoT). The server can resolve predefined domain
names locally and forward unknown queries to an upstream DNS server.

To demonstrate: - Socket programming using TCP and UDP\
- DNS packet handling and resolution logic\
- Secure communication using TLS\
- Handling multiple concurrent clients\
- Performance evaluation under load



## Features

-   UDP-based DNS server for fast query handling\
-   DNS-over-TLS (DoT) for encrypted DNS communication\
-   SSL/TLS control channel for secure client-server interaction\
-   Local DNS resolution with fallback to upstream DNS (8.8.8.8)\
-   Multithreaded server for handling multiple clients\
-   Benchmarking tool to measure latency and throughput


## Project Structure

-   server.py\
    Runs the DNS server. Supports UDP DNS, DNS-over-TLS, and SSL control
    channel.

-   client_test.py\
    Client program to send DNS queries (TLS or UDP) and test
    connectivity.

-   benchmark.py\
    Used to evaluate performance with multiple concurrent requests.

-   generate_cert.py\
    Generates self-signed SSL certificates (cert.pem, key.pem).


## Requirements

pip install dnslib pyopenssl


## Setup and Usage

1.  Generate SSL certificates (on server machine) python
    generate_cert.py

2.  Start the server python server.py

3.  Run the client (on another system) Update the server IP in
    client_test.py, then run: python client_test.py

4.  Run benchmark (optional) python benchmark.py


## How it works

-   The client sends a DNS query to the server\
-   The server checks if the domain exists in local records\
-   If found, it responds directly\
-   If not, the query is forwarded to an upstream DNS server (8.8.8.8)\
-   For secure communication, DNS queries can be sent over TLS


## Notes

-   Make sure all systems are on the same network (hotspot or LAN)\
-   Update server IP in client and benchmark files before running\
-   Open required ports if firewall blocks connections



