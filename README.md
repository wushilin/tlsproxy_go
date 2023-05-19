# tlsproxy_go
TLS Proxy written in golang

It listens on host port and forward to target SNI Host port. Supports almost all major TLS based protocols.


# Build
```bash
$ go build .
```

# Running
```bash
$ ./tlsproxy_go -b 0.0.0.0:443:443 -b 127.0.0.1:3465:465
```

It starts 2 listeners:

* one listens on 443, and forward the requests to SNI hosts port 443
* one listens on 3465, and forward the request to SNI hosts port 465

# Debug log
```bash
$ ./tlsproxy_go -b 0.0.0.0:443:443 -b 127.0.0.1:3465:465 -loglevel -1
```

# Enjoy