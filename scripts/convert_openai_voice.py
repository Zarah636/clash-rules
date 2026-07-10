#!/usr/bin/env python3
import ipaddress
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SOURCE_URL = "https://openai.com/chatgpt-voice.json"
OUTPUT_FILE = Path("OpenAI-Voice.list")
STATUS_FILE = Path("OpenAI-Voice.status.json")
FETCH_ATTEMPTS = 3
MIN_RULES = 10
MAX_RULES = 1000
WARN_SOURCE_AGE_DAYS = int(os.getenv("WARN_SOURCE_AGE_DAYS", "30"))
MAX_SOURCE_AGE_DAYS = int(os.getenv("MAX_SOURCE_AGE_DAYS", "180"))
STATUS_HEARTBEAT_DAYS = int(os.getenv("STATUS_HEARTBEAT_DAYS", "30"))
MAX_REMOVAL_RATIO = float(os.getenv("MAX_REMOVAL_RATIO", "0.50"))


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
                if response.status != 200:
                    raise OSError(f"unexpected HTTP status {response.status}")
                return json.load(response)
        except (OSError, json.JSONDecodeError) as error:
            if attempt == FETCH_ATTEMPTS:
                raise
            delay = attempt * 10
            print(f"Fetch attempt {attempt}/{FETCH_ATTEMPTS} failed: {error}. Retrying in {delay} seconds.", file=sys.stderr)
            time.sleep(delay)
    raise RuntimeError("OpenAI voice JSON fetch exhausted without a result.")


def parse_creation_time(value: object) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("missing or invalid creationTime")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("creationTime must include a timezone")
    return parsed.astimezone(timezone.utc)


def to_rule(prefix: str) -> str:
    network = ipaddress.ip_network(prefix, strict=False)
    kind = "IP-CIDR" if network.version == 4 else "IP-CIDR6"
    return f"{kind},{network}"


def extract_rules(data: object) -> set[str]:
    if not isinstance(data, dict) or not isinstance(data.get("prefixes"), list):
        raise ValueError("source JSON must contain a prefixes array")
    rules: set[str] = set()
    for index, item in enumerate(data["prefixes"]):
        if not isinstance(item, dict):
            raise ValueError(f"prefixes[{index}] must be an object")
        found = False
        for field in ("ipv4Prefix", "ipv6Prefix"):
            value = item.get(field)
            if value is not None:
                if not isinstance(value, str):
                    raise ValueError(f"prefixes[{index}].{field} must be a string")
                rules.add(to_rule(value))
                found = True
        if not found:
            raise ValueError(f"prefixes[{index}] contains no supported IP prefix")
    if not MIN_RULES <= len(rules) <= MAX_RULES:
        raise ValueError(f"suspicious ruleset size: {len(rules)} (expected {MIN_RULES}..{MAX_RULES})")
    return rules


def existing_rules() -> set[str]:
    if not OUTPUT_FILE.exists():
        return set()
    return {line for line in OUTPUT_FILE.read_text(encoding="utf-8").splitlines() if line.startswith(("IP-CIDR,", "IP-CIDR6,"))}


def validate_change(old: set[str], new: set[str]) -> None:
    if not old:
        return
    removed = old - new
    if len(removed) / len(old) > MAX_REMOVAL_RATIO:
        raise ValueError(f"refusing unusually destructive update: removing {len(removed)}/{len(old)} rules")


def read_status() -> dict:
    try:
        value = json.loads(STATUS_FILE.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def should_refresh_status(old_status: dict, creation_time: str, rules_changed: bool, now: datetime) -> bool:
    if rules_changed or old_status.get("sourceCreationTime") != creation_time:
        return True
    try:
        checked = parse_creation_time(old_status.get("lastCheckedAt"))
    except (ValueError, TypeError):
        return True
    return (now - checked).total_seconds() >= STATUS_HEARTBEAT_DAYS * 86400


def atomic_write(path: Path, content: str) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)


def main() -> int:
    try:
        data = fetch_json(SOURCE_URL)
        creation = parse_creation_time(data.get("creationTime"))
        rules = extract_rules(data)
        old_rules = existing_rules()
        validate_change(old_rules, rules)
    except (OSError, json.JSONDecodeError, ValueError, TypeError) as error:
        print(f"OpenAI voice update validation failed: {error}", file=sys.stderr)
        return 1

    now = datetime.now(timezone.utc)
    age_days = (now - creation).total_seconds() / 86400
    if age_days < -1:
        print("OpenAI voice update validation failed: creationTime is in the future", file=sys.stderr)
        return 1
    if age_days > MAX_SOURCE_AGE_DAYS:
        print(f"OpenAI voice update validation failed: source is {age_days:.1f} days old", file=sys.stderr)
        return 1
    if age_days > WARN_SOURCE_AGE_DAYS:
        print(f"::warning title=Stale upstream data::OpenAI source is {age_days:.1f} days old")

    creation_text = creation.isoformat().replace("+00:00", "Z")
    output = "\n".join([
        "# OpenAI ChatGPT Voice IP ruleset",
        f"# Source: {SOURCE_URL}",
        f"# Source creation time: {creation_text}",
        "# Format: Surge RULE-SET / mihomo classical text",
        "# Use with: RULE-SET,...,PROXY,no-resolve",
        *sorted(rules),
        "",
    ])
    rules_changed = output != (OUTPUT_FILE.read_text(encoding="utf-8") if OUTPUT_FILE.exists() else "")
    if rules_changed:
        atomic_write(OUTPUT_FILE, output)

    old_status = read_status()
    if should_refresh_status(old_status, creation_text, rules_changed, now):
        status = {
            "lastCheckedAt": now.isoformat().replace("+00:00", "Z"),
            "ruleCount": len(rules),
            "sourceAgeDays": round(age_days, 1),
            "sourceCreationTime": creation_text,
            "sourceUrl": SOURCE_URL,
            "stale": age_days > WARN_SOURCE_AGE_DAYS,
        }
        atomic_write(STATUS_FILE, json.dumps(status, indent=2, sort_keys=True) + "\n")

    print(f"Validated {len(rules)} rules; source age {age_days:.1f} days; rules changed={rules_changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
