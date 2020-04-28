#!/usr/bin/env python3
import datetime
import json
import logging
import os

import crontab
import requests

LOG_FILE = "/var/rpz_server/log"
BIND_DIR = "/etc/bind/"
NAMED_CONF = "/etc/bind/named.conf"

PROVIDERS = "resources/providers.json"
HEADER = "resources/rpz_header"
CUSTOM_NAMED_CONF = "resources/named.conf"

ZONE_TEMPLATE = '''
zone "{0}" {
        type master;
        file "{0}";
        allow-query { none; };
};
'''


def main() -> None:
    _configure_logs()
    if not _check_cron():
        logging.info("Cron job set to 04:00.")
    _build_config()
    _reload()


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
    cron = crontab.CronTab(user="fr")
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


def _build_config() -> None:
    # Read providers
    with open(PROVIDERS) as file:
        categories = json.load(file)["categories"]

    # Read zone header
    with open(HEADER) as h:
        header = h.read().replace("{SERIAL}", datetime.datetime.now().strftime("%Y%m%d%H"))

    # Build zones
    for category, content in categories.items():
        category_header = header.replace("{ZONE}", category)
        with open(BIND_DIR + content["filename"]) as zone:
            zone.write(category_header)
            for provider in content["providers"]:
                domains = requests.get(provider.rstrip()).iter_lines()
                for domain in domains:
                    domain, ok = __format_domain(domain)
                    if ok:
                        zone.write(domain)

    # Build named.conf
    with open(CUSTOM_NAMED_CONF) as file:
        custom_named_conf = file.read()

    policies = ""
    zones = ""
    for category, content in categories:
        policies += "zone {0}; ".format(content["filename"])
        zones += ZONE_TEMPLATE.format(content["filename"])

    custom_named_conf = custom_named_conf.replace("{POLICIES}", policies).replace("{ZONES}", zones)

    with open(NAMED_CONF, "w") as named_conf:
        named_conf.write(custom_named_conf)


def _reload():
    # TODO: rndc reload via bash
    pass


def __format_domain(domain: bytes) -> (str, bool):
    domain = str(domain, "utf-8").strip()
    if domain.startswith("#") or len(domain) == 0:
        return domain, False

    parts = domain.split(" ")
    if len(parts) >= 2:
        if parts[0].startswith("0.0.0.0") or parts[0].startswith("127.0.0.1"):
            domain = parts[1]
        else:
            return domain, False

    domain = domain.split("#")[0]  # Before comment
    domain += "        CNAME . \n"
    return domain, True


if __name__ == '__main__':
    main()
