#!/usr/bin/env python3
import ipaddress
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

SOURCE_URL = "https://openai.com/chatgpt-voice.json"
OUTPUT_FILE = Path("OpenAI-Voice.list")
FETCH_ATTEMPTS = 3
MIN_RULES = 10


def fetch_json(url: str) -> dict:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Zarah636/clash-rules OpenAI Voice ruleset updater",
            "Accept": "application/json",
        },
    )

    for attempt in range(1, FETCH_ATTEMPTS + 1):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.load(response)
        except (OSError, json.JSONDecodeError) as error:
            if attempt == FETCH_ATTEMPTS:
                raise
            delay = attempt * 10
            print(
                f"Fetch attempt {attempt}/{FETCH_ATTEMPTS} failed: {error}. "
                f"Retrying in {delay} seconds.",
                file=sys.stderr,
            )
            time.sleep(delay)

    raise RuntimeError("OpenAI voice JSON fetch exhausted without a result.")


def to_rule(prefix: str) -> str:
    network = ipaddress.ip_network(prefix, strict=False)
    if network.version == 4:
        return f"IP-CIDR,{network}"
    return f"IP-CIDR6,{network}"


def main() -> int:
    try:
        data = fetch_json(SOURCE_URL)
    except (OSError, json.JSONDecodeError) as error:
        print(f"Failed to fetch OpenAI voice JSON: {error}", file=sys.stderr)
        return 1

    prefixes = data.get("prefixes", [])

    rules = set()
    for item in prefixes:
        ipv4_prefix = item.get("ipv4Prefix")
        ipv6_prefix = item.get("ipv6Prefix")

        if ipv4_prefix:
            rules.add(to_rule(ipv4_prefix))
        if ipv6_prefix:
            rules.add(to_rule(ipv6_prefix))

    if len(rules) < MIN_RULES:
        print(
            f"Refusing to write suspiciously small ruleset: "
            f"{len(rules)} rules (minimum {MIN_RULES}).",
            file=sys.stderr,
        )
        return 1

    header = [
        "# OpenAI ChatGPT Voice IP ruleset",
        "# Source: https://openai.com/chatgpt-voice.json",
        "# Format: Surge RULE-SET / mihomo classical text",
        "# Use with: RULE-SET,...,PROXY,no-resolve",
    ]

    OUTPUT_FILE.write_text(
        "\n".join(header + sorted(rules)) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {len(rules)} rules to {OUTPUT_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
