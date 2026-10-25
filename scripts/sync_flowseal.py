#!/usr/bin/env python3
"""Import supported Flowseal general.bat parameters as declarative MacDPI profiles.

Remote batch files are data only and are never executed. Unknown desync modes or
options stop the import; the previous compatible profile remains unchanged.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import urllib.request
import urllib.parse

ROOT = Path(__file__).resolve().parent.parent
PROFILE = ROOT / "daemon/profiles/default.json"
API = "https://api.github.com/repos/Flowseal/zapret-discord-youtube/commits/main"
RAW = "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/"


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "MacDPI-profile-sync"})
    with urllib.request.urlopen(request, timeout=20) as response:
        data = response.read(256 * 1024 + 1)
    if len(data) > 256 * 1024:
        raise ValueError("upstream file exceeds size limit")
    return data


def options(block):
    result = {}
    for match in re.finditer(r'--([\w-]+)(?:=("[^"]*"|[^\s^]+))?', block):
        key, value = match.group(1), match.group(2) or ""
        if key in result:
            if key.startswith("dpi-desync"):
                raise ValueError("duplicate desync option needs compatibility review")
            result[key] += " " + value
        else:
            result[key] = value
    return result


def desync_keys(opts, allowed):
    unknown = {k for k in opts if k.startswith("dpi-desync") and k not in allowed}
    if unknown:
        raise ValueError("unsupported Flowseal options: " + ", ".join(sorted(unknown)))


def pattern_name(value):
    match = re.fullmatch(r'"?%BIN%([A-Za-z0-9_. -]+\.bin)"?', value)
    if not match:
        raise ValueError("unsupported pattern path")
    return match.group(1)


def bounded(value, low, high):
    number = int(value)
    if not low <= number <= high:
        raise ValueError("upstream parameter outside supported bounds")
    return number


def import_settings(profile, batch):
    blocks = [options(block) for block in batch.replace("^\n", " ").split("--new")]
    google = next((b for b in blocks if "list-google.txt" in b.get("hostlist", "")), None)
    general = next((b for b in blocks if "list-general.txt" in b.get("hostlist", "") and "filter-tcp" in b), None)
    quic = next((b for b in blocks if b.get("filter-udp") == "443" and "dpi-desync-fake-quic" in b), None)
    voice = next((b for b in blocks if b.get("filter-l7") == "discord,stun"), None)
    if not all((google, general, quic, voice)):
        raise ValueError("Flowseal layout changed; manual compatibility review required")
    files = {}
    for block, role in [(google, "google"), (general, "general")]:
        desync_keys(block, {"dpi-desync", "dpi-desync-split-seqovl", "dpi-desync-split-pos", "dpi-desync-split-seqovl-pattern"})
        if block.get("dpi-desync") != "multisplit" or block.get("dpi-desync-split-pos") != "1":
            raise ValueError("new TCP mode needs a MacDPI engine update")
        if block.get("ip-id", "zero") != "zero":
            raise ValueError("unsupported IPv4 ID policy")
        profile[role + "_overlap"] = bounded(block["dpi-desync-split-seqovl"], 1, 1200)
        files["tls_" + role] = pattern_name(block["dpi-desync-split-seqovl-pattern"])
    desync_keys(quic, {"dpi-desync", "dpi-desync-repeats", "dpi-desync-fake-quic"})
    desync_keys(voice, {"dpi-desync", "dpi-desync-repeats", "dpi-desync-fake-discord", "dpi-desync-fake-stun"})
    if quic.get("dpi-desync") != "fake" or voice.get("dpi-desync") != "fake":
        raise ValueError("new UDP mode needs a MacDPI engine update")
    if voice.get("dpi-desync-fake-discord") != voice.get("dpi-desync-fake-stun"):
        raise ValueError("separate Discord/STUN patterns require compatibility review")
    files["quic_google"] = pattern_name(quic["dpi-desync-fake-quic"])
    files["discord_udp"] = pattern_name(voice["dpi-desync-fake-discord"])
    files["stun"] = "stun2.bin"
    profile["quic_repeats"] = bounded(quic.get("dpi-desync-repeats", "1"), 1, 12)
    profile["voice_repeats"] = bounded(voice.get("dpi-desync-repeats", "1"), 1, 12)
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", help="Exact upstream SHA; defaults to the current main commit")
    parser.add_argument("--check", action="store_true", help="Validate and report without modifying files")
    args = parser.parse_args()
    profile = json.loads(PROFILE.read_text())
    commit = args.commit or json.loads(fetch(API))["sha"]
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ValueError("invalid upstream commit")
    if commit == profile["source_commit"] and not args.check:
        print("Flowseal source unchanged")
        return
    batch = fetch(RAW + commit + "/general.bat")
    files = import_settings(profile, batch.decode("utf-8-sig"))
    payloads = {}
    metadata = {"repository": "https://github.com/Flowseal/zapret-discord-youtube", "commit": commit,
                "files": {"general.bat": {"bytes": len(batch), "sha256": hashlib.sha256(batch).hexdigest()}}}
    for key, name in files.items():
        data = fetch(RAW + commit + "/bin/" + urllib.parse.quote(name))
        if not 1 <= len(data) <= 1400:
            raise ValueError("upstream pattern exceeds supported bounds")
        digest = hashlib.sha256(data).hexdigest()
        profile["patterns"][key] = {"data": base64.b64encode(data).decode(), "sha256": digest}
        payloads[name] = data
        metadata["files"]["bin/" + name] = {"bytes": len(data), "sha256": digest}
    if args.check:
        print("Compatible profile:", commit)
        return
    profile["revision"] += 1
    profile["version"] = str(profile["revision"]) + "-" + commit[:12]
    profile["source_commit"] = commit
    canonical = {"tls_general": "tls_clienthello_4pda_to.bin", "tls_google": "tls_clienthello_www_google_com.bin",
                 "quic_google": "quic_initial_www_google_com.bin", "discord_udp": "ACTIVE_DISCORD_UDP.bin", "stun": "stun2.bin"}
    for key, name in files.items():
        (ROOT / "daemon/patterns" / canonical[key]).write_bytes(payloads[name])
    (ROOT / "reference/flowseal/SOURCE.json").write_text(json.dumps(metadata, indent=2) + "\n")
    PROFILE.write_text(json.dumps(profile, ensure_ascii=False, indent=2) + "\n")
    print("Imported compatible profile:", profile["version"])


if __name__ == "__main__":
    main()
