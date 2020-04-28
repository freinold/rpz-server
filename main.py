#!/usr/bin/env python3
import datetime
import logging
import os

import crontab
import requests

LOG_FILE = "/var/rpz_server/log"
RPZ = "/etc/bind/db.rpz"

PROVIDERS = "resources/providers.list"
HEADER = "resources/rpz_header"


def main() -> None:
    _configure_logs()
    if not _check_cron():
        logging.info("Cron job set to 04:00.")
    _build_rpz()


def _configure_logs() -> None:
    if not os.path.isfile(LOG_FILE):
        os.mknod(LOG_FILE)
    # noinspection PyArgumentList
    logging.basicConfig(
        datefmt="%Y-%m-%d %H:%M:%S",
        filename=LOG_FILE,
        filemode="a",
        format="{asctime} - {levelname:8}: {message}",
        level=logging.INFO,
        style="{"
    )
    logging.info("rpz-Server script started.")


def _check_cron() -> bool:
    cron = crontab.CronTab(user="root")
    if len(cron.find_comment("Rebuild rpz and restart BIND9")) == 0:
        # Set this script as cron job every day at 04:00
        own_path = os.path.realpath(__file__)
        job = cron.new(command="python3 {0}".format(own_path),
                       comment="Rebuild rpz and restart BIND9")
        job.hour.on(4)
        cron.write()
        return False
    else:
        return True


def _build_rpz() -> None:
    ips = {}

    # Read providers
    with open(PROVIDERS) as p:
        providers = p.readlines()

    # Read header
    with open(HEADER) as h:
        header = h.read().replace("{SERIAL}", datetime.datetime.now().strftime("%Y%m%d%H"))

    with open(RPZ, "w") as rpz:
        rpz.write(header)
        for provider in providers:
            rpz.write("\n; " + provider)
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

    logging.info("IPs:\n{0}".format(ips))


if __name__ == '__main__':
    main()
