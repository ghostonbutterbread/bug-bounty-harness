from __future__ import annotations

from agents import scope_puller


def test_scope_puller_imports_as_package() -> None:
    assert scope_puller.canonical_program_slug("https://bugcrowd.com/engagements/demo") == "demo"
