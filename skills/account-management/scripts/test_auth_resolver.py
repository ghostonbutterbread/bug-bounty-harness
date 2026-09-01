import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).with_name("auth_resolver.py")
SPEC = importlib.util.spec_from_file_location("auth_resolver", SCRIPT)
assert SPEC and SPEC.loader
resolver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(resolver)


class HeaderReplayTests(unittest.TestCase):
    def test_replays_application_headers_without_an_auth_allowlist(self) -> None:
        headers = {
            "Authorization": "[test]",
            "X-App-Session": "[test]",
            "X-Custom-Auth-Context": "[test]",
            "Origin": "https://soundcloud.com",
            "Referer": "https://soundcloud.com/",
            "User-Agent": "test-agent",
            "Sec-Fetch-Site": "same-origin",
            "Cookie": "session=[test]",
            "Host": "soundcloud.com",
            "Connection": "keep-alive",
            "X-PwnFox-Color": "blue",
        }

        actual = resolver.selected_headers(headers)

        self.assertEqual(
            actual,
            {
                "Authorization": "[test]",
                "X-App-Session": "[test]",
                "X-Custom-Auth-Context": "[test]",
                "Origin": "https://soundcloud.com",
                "Referer": "https://soundcloud.com/",
                "User-Agent": "test-agent",
                "Sec-Fetch-Site": "same-origin",
            },
        )


if __name__ == "__main__":
    unittest.main()
