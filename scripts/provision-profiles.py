# /// script
# requires-python = ">=3.11"
# dependencies = ["pyjwt[crypto]==2.10.1", "requests==2.32.5"]
# ///
"""Create the Developer ID provisioning profiles a release needs, through the App Store Connect API.

The app and its system extension carry the Network Extension entitlement, which only a
provisioning profile can grant, and Developer ID signing needs Developer ID ("direct
distribution") profiles: they are what allow the `packet-tunnel-provider-systemextension`
value. Xcode can make them itself, but its account login has proved unreliable, so this does it
with the same App Store Connect API key the notary profile uses.

Registers the bundle IDs if they are missing, turns on their capabilities, creates a fresh
profile for each against the Developer ID Application certificate, and writes them to
build/profiles/ (gitignored). Profiles aren't secret, but they're per-team, so they stay out of
the repo.

    uv run --locked scripts/provision-profiles.py
    WOMBAT_BUNDLE_ID=org.example.wombat uv run --locked scripts/provision-profiles.py   # a fork

Env (required): ASC_KEY_ID, ASC_ISSUER_ID; optional ASC_KEY_PATH (default
~/.appstoreconnect/private_keys/AuthKey_<id>.p8). The key needs the Admin or App Manager role:
Developer-role keys (fine for notarization) get 403 on bundle IDs and profiles.
"""
import base64
import os
import pathlib
import sys
import time

import jwt
import requests

KEY_ID = os.environ.get("ASC_KEY_ID") or sys.exit("set ASC_KEY_ID (App Store Connect API key ID)")
ISSUER = os.environ.get("ASC_ISSUER_ID") or sys.exit("set ASC_ISSUER_ID (App Store Connect issuer ID)")
KEY_PATH = pathlib.Path(os.environ.get("ASC_KEY_PATH", f"~/.appstoreconnect/private_keys/AuthKey_{KEY_ID}.p8")).expanduser()
APP_ID = os.environ.get("WOMBAT_BUNDLE_ID", "net.vpetkov.wombat")
API = "https://api.appstoreconnect.apple.com/v1"

TARGETS = [
    # (identifier, display name, capabilities)
    (APP_ID, "Wombat", ["NETWORK_EXTENSIONS", "SYSTEM_EXTENSION_INSTALL"]),
    (APP_ID + ".tunnel", "Wombat Tunnel", ["NETWORK_EXTENSIONS"]),
    (APP_ID + ".openconnect", "Wombat OpenConnect", ["NETWORK_EXTENSIONS"]),
]


def token() -> str:
    now = int(time.time())
    return jwt.encode({"iss": ISSUER, "iat": now, "exp": now + 900, "aud": "appstoreconnect-v1"},
                      KEY_PATH.read_text(), algorithm="ES256", headers={"kid": KEY_ID})


def call(method: str, path: str, body: dict | None = None) -> dict:
    r = requests.request(method, API + path, headers={"Authorization": f"Bearer {token()}"}, json=body, timeout=60)
    if r.status_code >= 400:
        sys.exit(f"{method} {path}: HTTP {r.status_code}\n{r.text}")
    return r.json() if r.text else {}


def bundle_id(identifier: str, name: str) -> str:
    found = [b for b in call("GET", f"/bundleIds?filter[identifier]={identifier}&limit=200")["data"]
             if b["attributes"]["identifier"] == identifier]  # the filter is a prefix match
    if found:
        return found[0]["id"]
    print(f"registering {identifier}")
    return call("POST", "/bundleIds", {"data": {"type": "bundleIds", "attributes": {
        "identifier": identifier, "name": name, "platform": "MAC_OS"}}})["data"]["id"]


def enable(bid: str, capabilities: list[str]) -> None:
    have = {c["attributes"]["capabilityType"] for c in call("GET", f"/bundleIds/{bid}/bundleIdCapabilities")["data"]}
    for cap in capabilities:
        if cap in have:
            continue
        print(f"  enabling {cap}")
        call("POST", "/bundleIdCapabilities", {"data": {"type": "bundleIdCapabilities",
             "attributes": {"capabilityType": cap},
             "relationships": {"bundleId": {"data": {"type": "bundleIds", "id": bid}}}}})


def developer_id_certificate() -> str:
    certs = [c for c in call("GET", "/certificates?limit=200")["data"]
             if c["attributes"]["certificateType"] in ("DEVELOPER_ID_APPLICATION", "DEVELOPER_ID_APPLICATION_G2")]
    if not certs:
        sys.exit("no Developer ID Application certificate on this team")
    return max(certs, key=lambda c: c["attributes"]["expirationDate"])["id"]


def main() -> None:
    out = pathlib.Path(__file__).resolve().parent.parent / "build" / "profiles"
    out.mkdir(parents=True, exist_ok=True)
    cert = developer_id_certificate()
    for identifier, name, capabilities in TARGETS:
        bid = bundle_id(identifier, name)
        enable(bid, capabilities)
        profile_name = f"{identifier} Developer ID"
        # A profile is a snapshot of its bundle ID's capabilities: replace any older one.
        for p in call("GET", f"/profiles?filter[name]={profile_name}&limit=200")["data"]:
            if p["attributes"]["name"] == profile_name:
                call("DELETE", f"/profiles/{p['id']}")
        created = call("POST", "/profiles", {"data": {"type": "profiles",
                       "attributes": {"name": profile_name, "profileType": "MAC_APP_DIRECT"},
                       "relationships": {
                           "bundleId": {"data": {"type": "bundleIds", "id": bid}},
                           "certificates": {"data": [{"type": "certificates", "id": cert}]}}}})["data"]
        path = out / f"{identifier}.provisionprofile"
        path.write_bytes(base64.b64decode(created["attributes"]["profileContent"]))
        print(f"{identifier}: {path} (uuid {created['attributes']['uuid']})")


if __name__ == "__main__":
    main()
