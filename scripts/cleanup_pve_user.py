#!/usr/bin/env python3
import argparse
import csv
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
        # Set auth cookie
        self.session.cookies.set("PVEAuthCookie", ticket)

    def _headers(self) -> dict:
        headers = {}
        if self.csrf:
            headers["CSRFPreventionToken"] = self.csrf
        return headers

    def _user_path(self, userid: str) -> str:
        # The userid must be url-encoded because it contains '@'
        return f"{self.base_url}/access/users/{urllib.parse.quote(userid, safe='')}"

    def list_users(self) -> list:
        resp = self.session.get(f"{self.base_url}/access/users", verify=self.verify_ssl)
        if resp.status_code != 200:
            raise RuntimeError(f"Failed to list users: HTTP {resp.status_code} {resp.text}")
        return resp.json().get("data", [])

    def user_exists(self, userid: str) -> bool:
        # Try direct GET first; fallback to listing on 404 for older versions
        url = self._user_path(userid)
        resp = self.session.get(url, verify=self.verify_ssl)
        if resp.status_code == 200:
            return True
        if resp.status_code not in (404, 501):
            # Some clusters may not support GET-by-id; fallback to list
            pass
        # Fallback: list all users and search
        users = self.list_users()
        return any(u.get("userid") == userid for u in users)

    def delete_user(self, userid: str) -> bool:
        # Returns True if deleted, False if not found
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
    parser = argparse.ArgumentParser(description="Iterate range_users.csv; if <user>@ad exists, delete <user>@pve. Log PVE-only users.")
    parser.add_argument("--csv", dest="csv_path", default=os.environ.get("RANGE_CSV", os.path.join(os.path.dirname(__file__), "range_users.csv")), help="Path to range_users.csv (default: repo file or $RANGE_CSV)")
    parser.add_argument("--log", dest="log_path", default=os.environ.get("PVE_ONLY_LOG", os.path.join(os.path.dirname(__file__), "pve_only_users.log")), help="Path to write PVE-only users log")
    parser.add_argument("--host", default=os.environ.get("PVE_HOST"), help="Proxmox host (without https://), default from $PVE_HOST")
    parser.add_argument("--api-user", default=os.environ.get("PVE_USER"), help="API username (without realm), default from $PVE_USER")
    parser.add_argument("--realm", default=os.environ.get("PVE_REALM", "pve"), help="Realm for API user (default: pve or from $PVE_REALM)")
    parser.add_argument("--password", default=os.environ.get("PVE_PASSWORD"), help="API user password, default from $PVE_PASSWORD")
    parser.add_argument("--verify-ssl", default=os.environ.get("PVE_VERIFY_SSL", "true"), help="Verify SSL (true/false), default true or $PVE_VERIFY_SSL")
    parser.add_argument("--dry-run", action="store_true", help="Only print actions; do not delete users")

    args = parser.parse_args()

    if not os.path.isfile(args.csv_path):
        print(f"ERROR: CSV not found: {args.csv_path}", file=sys.stderr)
        return 2
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

        # Preload user list once to reduce API calls
        users = client.list_users()
        user_ids = set(u.get("userid") for u in users if u.get("userid"))

        pve_only = []

        with open(args.csv_path, newline="") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row:
                    continue
                base = row[0].strip()
                if not base:
                    continue
                user_ad = f"{base}@ad"
                user_pve = f"{base}@pve"

                ad_exists = user_ad in user_ids
                pve_exists = user_pve in user_ids

                if ad_exists and pve_exists:
                    if args.dry_run:
                        print(f"[DRYRUN] Would delete {user_pve}")
                    else:
                        if client.delete_user(user_pve):
                            print(f"[OK] Deleted {user_pve}")
                        else:
                            print(f"[SKIP] {user_pve} not found at delete time")
                elif (not ad_exists) and pve_exists:
                    print(f"[PVE-ONLY] {user_pve} exists; {user_ad} missing")
                    pve_only.append(base)
                else:
                    print(f"[INFO] {base}: ad={ad_exists} pve={pve_exists}")

        if pve_only:
            with open(args.log_path, "w", encoding="utf-8") as lf:
                for base in pve_only:
                    lf.write(f"{base}\n")
            print(f"[LOG] Wrote PVE-only users to {args.log_path} ({len(pve_only)} entries)")
        else:
            print("[LOG] No PVE-only users found")

        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())


