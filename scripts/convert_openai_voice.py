#!/usr/bin/env python3
import ipaddress
import json
import sys
import urllib.request
from pathlib import Path

SOURCE_URL = "https://openai.com/chatgpt-voice.json"
OUTPUT_FILE = Path("OpenAI-Voice.list")


def fetch_json(url: str) -> dict:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Zarah636/clash-rules OpenAI Voice ruleset updater",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def to_rule(prefix: str) -> str:
    network = ipaddress.ip_network(prefix, strict=False)
    if network.version == 4:
        return f"IP-CIDR,{network}"
    return f"IP-CIDR6,{network}"


def main() -> int:
    data = fetch_json(SOURCE_URL)
    prefixes = data.get("prefixes", [])

    rules = set()
    for item in prefixes:
        ipv4_prefix = item.get("ipv4Prefix")
        ipv6_prefix = item.get("ipv6Prefix")

        if ipv4_prefix:
            rules.add(to_rule(ipv4_prefix))
        if ipv6_prefix:
            rules.add(to_rule(ipv6_prefix))

    if not rules:
        print("No IP prefixes found in OpenAI voice JSON.", file=sys.stderr)
        return 1

    header = [
        "# OpenAI ChatGPT Voice IP ruleset",
        "# Source: https://openai.com/chatgpt-voice.json",
        "# Format: Surge RULE-SET / mihomo classical text",
        "# Use with: RULE-SET,...,PROXY,no-resolve",
    ]

    OUTPUT_FILE.write_text("\n".join(header + sorted(rules)) + "\n", encoding="utf-8")
    print(f"Wrote {len(rules)} rules to {OUTPUT_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
