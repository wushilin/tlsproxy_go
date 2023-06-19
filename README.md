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

# Avoid connecting to self
The program will cause infinite loop if it connects to itself. To avoid that, you can specify a self ip by
-selfip "ip1;ip2"

When SNI info points to host that would resolve to one of the self IP addresses, the connection will be rejected.

# Debug log
```bash
$ ./tlsproxy_go -b 0.0.0.0:443:443 -b 127.0.0.1:3465:465 -loglevel 0
```
Log level higher less verbose. Smallest is 0

# ACL
You can use `-acl rule.json` to specify a ACL for host check. 
This will help you to limit the target host names by static check, or by regular expression.

See `rules.json` in the repo for more info.

Example

```json
{
    "no_match_decision":"reject",
    "whitelist":[
        "host:a",
        "host:www.google.com",
        "pattern:www\\.goo.*\\.com"
    ],
    "blacklist":[
        "host:a",
        "host:b",
        "pattern:www.goddogle.com"
    ]
}
```

The rule says: When no whitelist/blacklist is matching the host, the decision will be "reject" (valid options are "accept", "reject"),

whitelist and blacklist are hosts that are allowed or rejected. 

All checks are case insensitive.

`host:xxx` is valid just for host xxx using exact match.
`pattern:xxx` is valid if regular expression xxx matches the host name to connect.


# Enjoy
