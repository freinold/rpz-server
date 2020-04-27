#!/usr/bin/env python3
import datetime

import requests

HEADER = '''; zone file db.rpz
$TTL 1H
@                       SOA LOCALHOST. named-mgr.example.com ({0} 1h 15m 30d 2h)
                        NS  LOCALHOST.
; begin RPZ RR definitions
'''

with open("../dns-firewall/providers.list") as p:
    providers = p.readlines()

ips = {}

with open("../dns-firewall/db.rpz", "w") as rpz:
    rpz.write(HEADER.format(datetime.datetime.now().strftime("%Y%m%d%H")))
    for provider in providers:
        rpz.write("\n; "+provider)
        domains = requests.get(provider.rstrip()).iter_lines()
        for domain in domains:
            domain = str(domain, "utf-8").strip()
            if domain.startswith("#") or len(domain) == 0:
                continue

            parts = domain.split(" ")
            if len(parts) >= 2:
                # Only to see if we got the right ones
                ip = parts[0].rstrip()
                if ip not in ips:
                    ips[ip] = 1
                else:
                    ips[ip] += 1

                if parts[0].startswith("0.0.0.0") or parts[0].startswith("127.0.0.1"):
                    domain = parts[1]
                else:
                    continue

            domain = domain.split("#")[0]  # Before comment
            domain += "        CNAME . \n"
            rpz.write(domain)

print(ips)
