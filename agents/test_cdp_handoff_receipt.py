import json
import os
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "skills" / "chromium-handoff" / "scripts" / "cdp_handoff_server.js"


def run_server(receipt_path: Path):
    env = os.environ | {
        "BROWSER_LAUNCH_RECEIPT": str(receipt_path),
        "CDP_URL": "http://127.0.0.1:9224",
        "LISTEN_PORT": "9567",
    }
    return subprocess.run(
        ["timeout", "2s", "node", str(SERVER)],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def trusted_fallback_receipt():
    return {
        "cdp_url": "http://127.0.0.1:9224",
        "display_fallback": {
            "from": "kasmvnc",
            "to": "default",
            "reason": "KasmVNC CDP readiness failed",
        },
        "proxy_cert_mode": "import",
        "proxy_cert_status": {"status": "trusted"},
    }


@pytest.mark.parametrize(
    ("mutate", "expected_error"),
    [
        (lambda receipt: receipt.pop("display_fallback"), "display_fallback"),
        (lambda receipt: receipt.update(proxy_cert_mode="auto"), "proxy_cert_mode"),
        (lambda receipt: receipt.update(proxy_cert_status={"status": "ignored-by-flag"}), "proxy_cert_status"),
        (lambda receipt: receipt.update(cdp_url="http://127.0.0.1:9225"), "cdp_url"),
        (lambda receipt: None, "live browser pid"),
    ],
)
def test_cdp_handoff_rejects_unqualified_fallback_receipts(tmp_path, mutate, expected_error):
    receipt = trusted_fallback_receipt()
    mutate(receipt)
    receipt_path = tmp_path / "launch.json"
    receipt_path.write_text(json.dumps(receipt))

    result = run_server(receipt_path)

    assert result.returncode == 1
    assert expected_error in result.stderr


def test_cdp_handoff_rejects_receipt_not_bound_to_live_browser(tmp_path):
    receipt_path = tmp_path / "launch.json"
    receipt = trusted_fallback_receipt() | {
        "pid": os.getpid(),
        "profile_dir": "/tmp/not-the-browser-profile",
    }
    receipt_path.write_text(json.dumps(receipt))

    result = run_server(receipt_path)

    assert result.returncode == 1
    assert "does not match the receipt CDP endpoint and profile" in result.stderr
