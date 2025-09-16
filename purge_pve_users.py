#!/usr/bin/env python3
import argparse
import os
import sys
import urllib.parse
import requests


class ProxmoxAPIClient:
    def __init__(self, host: str, username: str, password: str, realm: str = "pve", verify_ssl: bool = True):
        self.base_url = f"https://{host}:8006/api2/json"
        self.auth_user = f"{username}@{realm}" if "@" not in username else username
        self.password = password
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.csrf = None

    def login(self) -> None:
        url = f"{self.base_url}/access/ticket"
        resp = self.session.post(url, data={"username": self.auth_user, "password": self.password}, verify=self.verify_ssl)
        if resp.status_code != 200:
            raise RuntimeError(f"Login failed: HTTP {resp.status_code} {resp.text}")
        data = resp.json().get("data", {})
        ticket = data.get("ticket")
        self.csrf = data.get("CSRFPreventionToken")
        if not ticket or not self.csrf:
            raise RuntimeError("Login failed: missing ticket or CSRF token")
        self.session.cookies.set("PVEAuthCookie", ticket)

    def _headers(self) -> dict:
        headers = {}
        if self.csrf:
            headers["CSRFPreventionToken"] = self.csrf
        return headers

    def _user_path(self, userid: str) -> str:
        return f"{self.base_url}/access/users/{urllib.parse.quote(userid, safe='')}"

    def list_users(self) -> list:
        resp = self.session.get(f"{self.base_url}/access/users", verify=self.verify_ssl)
        if resp.status_code != 200:
            raise RuntimeError(f"Failed to list users: HTTP {resp.status_code} {resp.text}")
        return resp.json().get("data", [])

    def delete_user(self, userid: str) -> bool:
        url = self._user_path(userid)
        resp = self.session.delete(url, headers=self._headers(), verify=self.verify_ssl)
        if resp.status_code == 200:
            return True
        if resp.status_code == 404:
            return False
        raise RuntimeError(f"Failed to delete {userid}: HTTP {resp.status_code} {resp.text}")


def parse_bool(value: str, default: bool) -> bool:
    if value is None:
        return default
    value = value.strip().lower()
    return value in ("1", "true", "t", "yes", "y", "on")


def main() -> int:
    parser = argparse.ArgumentParser(description="Purge all users in the 'pve' domain via Proxmox API")
    parser.add_argument("--host", default=os.environ.get("PVE_HOST"), help="Proxmox host (without https://), default from $PVE_HOST")
    parser.add_argument("--api-user", default=os.environ.get("PVE_USER"), help="API username (without realm), default from $PVE_USER")
    parser.add_argument("--realm", default=os.environ.get("PVE_REALM", "pve"), help="Realm for API user (default: pve or from $PVE_REALM)")
    parser.add_argument("--password", default=os.environ.get("PVE_PASSWORD"), help="API user password, default from $PVE_PASSWORD")
    parser.add_argument("--verify-ssl", default=os.environ.get("PVE_VERIFY_SSL", "true"), help="Verify SSL (true/false), default true or $PVE_VERIFY_SSL")
    parser.add_argument("--dry-run", action="store_true", help="Only print actions; do not delete users")

    args = parser.parse_args()

    if not args.host:
        print("ERROR: --host or $PVE_HOST is required", file=sys.stderr)
        return 2
    if not args.api_user:
        print("ERROR: --api-user or $PVE_USER is required", file=sys.stderr)
        return 2
    if not args.password:
        print("ERROR: --password or $PVE_PASSWORD is required", file=sys.stderr)
        return 2

    verify_ssl = parse_bool(args.verify_ssl, True)

    client = ProxmoxAPIClient(
        host=args.host,
        username=args.api_user,
        password=args.password,
        realm=args.realm,
        verify_ssl=verify_ssl,
    )

    try:
        client.login()
        users = client.list_users()
        pve_users = [u.get("userid") for u in users if u.get("userid", "").endswith("@pve")]

        if not pve_users:
            print("[INFO] No @pve users found")
            return 0

        for uid in pve_users:
            if args.dry_run:
                print(f"[DRYRUN] Would delete {uid}")
                continue
            deleted = client.delete_user(uid)
            if deleted:
                print(f"[OK] Deleted {uid}")
            else:
                print(f"[SKIP] Not found at delete time: {uid}")

        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())


