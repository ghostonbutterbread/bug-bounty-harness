#!/usr/bin/env python3
"""Prepare a Chromium profile to trust a mitmproxy CA certificate."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


DEFAULT_CA_CERT = Path("~/.mitmproxy/mitmproxy-ca-cert.pem").expanduser()
DEFAULT_CERT_NAME = "mitmproxy"


def certutil_path() -> str | None:
    return shutil.which("certutil")


def has_nss_db(profile_dir: Path) -> bool:
    return (profile_dir / "cert9.db").exists() and (profile_dir / "key4.db").exists()


def run_certutil(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def ensure_nss_db(profile_dir: Path, certutil: str) -> dict[str, Any]:
    profile_dir.mkdir(parents=True, exist_ok=True)
    if has_nss_db(profile_dir):
        return {"created": False}

    proc = run_certutil(
        [certutil, "-d", f"sql:{profile_dir}", "-N", "--empty-password"]
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "certutil -N failed")
    return {"created": True}


def certificate_exists(profile_dir: Path, certutil: str, cert_name: str) -> bool:
    proc = run_certutil([certutil, "-d", f"sql:{profile_dir}", "-L", "-n", cert_name])
    return proc.returncode == 0


def delete_certificate(profile_dir: Path, certutil: str, cert_name: str) -> None:
    proc = run_certutil([certutil, "-d", f"sql:{profile_dir}", "-D", "-n", cert_name])
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "certutil -D failed")


def import_certificate(profile_dir: Path, ca_cert: Path, certutil: str, cert_name: str) -> None:
    proc = run_certutil(
        [
            certutil,
            "-d",
            f"sql:{profile_dir}",
            "-A",
            "-t",
            "C,,",
            "-n",
            cert_name,
            "-i",
            str(ca_cert),
        ]
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "certutil -A failed")


def prepare_nss_db(
    nss_dir: Path,
    ca_cert: Path,
    certutil: str,
    cert_name: str,
    replace: bool,
) -> dict[str, Any]:
    db = ensure_nss_db(nss_dir, certutil)
    existed = certificate_exists(nss_dir, certutil, cert_name)
    if existed and replace:
        delete_certificate(nss_dir, certutil, cert_name)
        existed = False
    if not existed:
        import_certificate(nss_dir, ca_cert, certutil, cert_name)
    return {
        "nss_dir": str(nss_dir),
        "nss_db_created": db["created"],
        "already_present": existed,
    }


def prepare_profile_ca(
    profile_dir: Path,
    ca_cert: Path = DEFAULT_CA_CERT,
    cert_name: str = DEFAULT_CERT_NAME,
    replace: bool = True,
    home_dir: Path | None = None,
) -> dict[str, Any]:
    certutil = certutil_path()
    if not certutil:
        return {
            "status": "missing-certutil",
            "profile_dir": str(profile_dir),
            "ca_cert": str(ca_cert),
            "cert_name": cert_name,
        }
    if not ca_cert.exists():
        return {
            "status": "missing-ca-cert",
            "profile_dir": str(profile_dir),
            "ca_cert": str(ca_cert),
            "cert_name": cert_name,
        }

    profile_result = prepare_nss_db(profile_dir, ca_cert, certutil, cert_name, replace)
    nss_results = [profile_result]
    if home_dir:
        home_nss = home_dir / ".pki" / "nssdb"
        nss_results.append(prepare_nss_db(home_nss, ca_cert, certutil, cert_name, replace))

    return {
        "status": "trusted",
        "profile_dir": str(profile_dir),
        "home_dir": str(home_dir) if home_dir else None,
        "ca_cert": str(ca_cert),
        "cert_name": cert_name,
        "nss_dbs": nss_results,
        "nss_db_created": any(item["nss_db_created"] for item in nss_results),
        "already_present": all(item["already_present"] for item in nss_results),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Import a mitmproxy CA certificate into a Chromium profile NSS DB."
    )
    parser.add_argument("--profile-dir", required=True, help="Chromium user-data-dir/profile root.")
    parser.add_argument(
        "--ca-cert",
        default=str(DEFAULT_CA_CERT),
        help="CA certificate to trust. Defaults to ~/.mitmproxy/mitmproxy-ca-cert.pem.",
    )
    parser.add_argument(
        "--cert-name",
        default=DEFAULT_CERT_NAME,
        help="Nickname to use in the Chromium profile NSS DB.",
    )
    parser.add_argument(
        "--home-dir",
        help="Optional isolated HOME directory. Also imports into HOME/.pki/nssdb.",
    )
    parser.add_argument(
        "--no-replace",
        action="store_true",
        help="Leave an existing certificate with the same nickname untouched.",
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = prepare_profile_ca(
        Path(args.profile_dir).expanduser(),
        Path(args.ca_cert).expanduser(),
        args.cert_name,
        replace=not args.no_replace,
        home_dir=Path(args.home_dir).expanduser() if args.home_dir else None,
    )

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"{result['status']}: {result['profile_dir']}")
        print(f"CA: {result['ca_cert']}")
    return 0 if result["status"] == "trusted" else 2


if __name__ == "__main__":
    raise SystemExit(main())
