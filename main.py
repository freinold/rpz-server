#!/usr/bin/env python3
import datetime
import ipaddress
import itertools
import json
import logging
import os
import re

import crontab
import requests

import bash

LOG_FILE = "/var/rpz_server/log"
BIND_DIR = "/etc/bind/"
NAMED_CONF = "/etc/bind/named.conf"

PROVIDERS = "resources/providers.json"
HEADER = "resources/rpz_header"
CUSTOM_NAMED_CONF = "resources/named.conf"

ZONE_TEMPLATE = '''
zone "{0}" {{
        type master;
        file "{0}";
        allow-query {{ none; }};
}};
'''


def main() -> None:
    # configure_logs()
    # if not check_cron():
    #     logging.info("Cron job set to 04:00.")

    domain_categories, ip_range_lists = providers_from_json(PROVIDERS)

    domains_per_category = get_domains(domain_categories)

    with open(HEADER) as file:
        header = file.read().replace("{SERIAL}", datetime.datetime.now().strftime("%Y%m%d%H"))

    domain_zones, domain_policies = generate_domain_zones(domain_categories, domains_per_category, header)
    ip_zone, ip_policy = generate_ip_zone(ip_range_lists, header)

    zones = domain_zones + ip_zone
    policies = domain_policies + ip_policy

    build_named_conf(zones, policies)

    load()


def configure_logs() -> None:
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


def check_cron() -> bool:
    cron = crontab.CronTab(user="fr")
    if len(cron.find_comment("Rebuild zones and restart BIND9")) == 0:
        # Set this script as cron job every day at 04:00
        own_path = os.path.realpath(__file__)
        job = cron.new(command="python3 {0}".format(own_path),
                       comment="Rebuild zones and restart BIND9")
        job.hour.on(4)
        cron.write()
        return False
    else:
        return True


def providers_from_json(filename: str) -> (dict, list):
    with open(filename) as file:
        content = json.load(file)
    categories = content["domain_categories"]
    ip_range_lists = content["ip_range_lists"]
    return categories, ip_range_lists


def get_domains(domain_categories: dict) -> dict:
    domains_per_category = {}
    for category_id, data in domain_categories.items():
        domains_per_category[category_id] = []
        for provider in data["providers"]:
            domains = requests.get(provider).iter_lines()
            for domain in domains:
                domain, ok = _format_domain(domain)
                if ok:
                    domains_per_category[category_id].append(domain)
    return domains_per_category


def generate_domain_zones(domain_categories: dict, domains_per_category: dict, header: str):
    zones, policies = "", ""
    max_category_id = int(max(list(domain_categories)))
    for category_combination in _category_combinations(max_category_id):
        combination_id = sum(map(lambda x: 2 ** x, category_combination))
        description_list = map(lambda x: domain_categories[str(x)]["description"], category_combination)
        filename = BIND_DIR + "db.combination.{0}".format(combination_id)
        zones += ZONE_TEMPLATE.format(filename)
        policies += 'zone "{0}"; '.format(filename)
        combination_header = header.replace("{ZONE}", "block.{0}: Combination of {1}".format(combination_id, ", ".join(
            description_list)))
        with open(filename, "w") as file:
            file.write(combination_header)
            for category_id in category_combination:
                file.write("\n".join(domains_per_category[str(category_id)]) + "\n")
    return zones, policies


def generate_ip_zone(ip_range_lists, header):
    ip_range_header = header.replace("{ZONE}", "block.ip_range")
    filename = BIND_DIR + "db.ip"
    with open(filename, "w") as file:
        file.write(ip_range_header)
        for ip_range_list in ip_range_lists:
            ip_ranges = requests.get(ip_range_list).iter_lines()
            format_ip = _format_ipv6 if "v6" in ip_range_list else _format_ipv4  # Pick correct format function
            for ip_range in ip_ranges:
                ip_range, ok = format_ip(ip_range)
                if ok:
                    file.write(ip_range + "\n")
    return ZONE_TEMPLATE.format(filename), 'zone "{0}";'.format(filename)


def build_named_conf(zones: str, policies: str):
    with open(CUSTOM_NAMED_CONF) as file:
        custom_named_conf = file.read()

    custom_named_conf = custom_named_conf.replace("{POLICIES}", policies).replace("{ZONES}", zones)

    with open(NAMED_CONF, "w") as named_conf:
        named_conf.write(custom_named_conf)


def load():
    output = bash.call("systemctl is-active bind9")
    if output == "active":
        # Reload via rndc
        bash.call("sudo rndc reload")
    else:
        # Start via systemctl
        bash.call("sudo systemctl start bind9")


def _category_combinations(n: int) -> list:
    categories = range(n + 1)
    combinations = list(
        itertools.chain.from_iterable(itertools.combinations(categories, r) for r in range(len(categories) + 1)))
    return sorted(combinations, key=sum)[1:]


def _format_domain(domain: bytes) -> (str, bool):
    domain = str(domain, "utf-8").strip()
    if domain.startswith("#") or len(domain) == 0:
        return domain, False

    parts = domain.split()
    if len(parts) >= 2:
        if parts[0].startswith("0.0.0.0") or parts[0].startswith("127.0.0.1"):
            domain = parts[1]
        else:
            return domain, False

    domain = domain.split("#")[0]  # Before comment
    domain += "\tCNAME . "
    return domain, True


def _format_ipv4(ip_range: bytes) -> (str, bool):
    ip_range = str(ip_range, "utf-8").strip()
    if ip_range.startswith(";"):
        return ip_range, False
    o1, o2, o3, o4, m = re.split(r"(\d+)\.(\d+)\.(\d+)\.(\d+)/(\d+)", ip_range)[1:6]
    return "{0}.{1}.{2}.{3}.{4}.rpz-ip.\tCNAME . ".format(m, o4, o3, o2, o1), True


def _format_ipv6(ip_range: bytes) -> (str, bool):
    ip_range = str(ip_range, "utf-8")
    if ip_range.startswith(";"):
        return ip_range, False
    ip_range = ip_range.split(";")[0].strip()
    notation = ipaddress.IPv6Network(ip_range).exploded.replace("/", ":").split(":")
    notation.reverse()
    return "{0}.rpz-ip\tCNAME . ".format(".".join(notation)), True


if __name__ == '__main__':
    main()
