"""Manager-read, non-secret policy for a future browser auth-transfer caller.

This module does not read browser state, perform requests, or authorize transfer.
The caller must independently bind the pool and enforce no-follow redirects while
requesting the fixed check URL; verify_check_response is the post-request gate.
"""

from __future__ import annotations

import json
import os
import re
import stat
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


class SiteContractError(ValueError):
    """Safe, non-secret refusal; never includes untrusted config values."""


# Bounded common two-label public suffixes, not a public-suffix database.
_SECOND_LEVEL_SUFFIXES = {
    'ac.uk', 'co.uk', 'gov.uk', 'org.uk', 'com.au', 'net.au', 'org.au',
    'co.nz', 'co.jp', 'co.in', 'com.br', 'com.cn', 'com.mx', 'com.sg',
    'github.io', 'appspot.com', 'pages.dev', 'vercel.app',
}


@dataclass(frozen=True)
class SiteContract:
    program: str
    auth_domain: str
    account_alias: str
    allowed_origins: tuple[str, ...]
    check_url: str
    principal_selector: str
    expected_principal: str
    local_storage_keys: tuple[str, ...]
    cookie_name: str
    cookie_domain: str
    cookie_path: str


def _object(value: object, keys: set[str]) -> dict:
    if type(value) is not dict or set(value) != keys:
        raise SiteContractError("Unsupported site contract shape")
    return value


def _text(value: object) -> str:
    if type(value) is not str or not value or value != value.strip() or any(ord(c) < 32 for c in value):
        raise SiteContractError("Invalid site contract field")
    return value


def _domain(value: object) -> str:
    name = _text(value)
    if (name != name.lower() or '*' in name or name.startswith('.') or
            not re.fullmatch(r'[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?)*', name)):
        raise SiteContractError("Invalid site contract domain")
    return name


def _url(value: object, *, origin: bool = False, fixture: bool = False) -> tuple[str, str]:
    value = _text(value)
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise SiteContractError("Invalid site contract URL") from exc
    host = parsed.hostname
    if (not host or parsed.username is not None or parsed.password is not None or
            parsed.fragment or parsed.query or not _domain(host) == host or
            parsed.netloc != (host + (f':{port}' if port is not None else '')) or
            parsed.scheme not in ('https', 'http') or
            (port is not None and port == (443 if parsed.scheme == 'https' else 80)) or
            (parsed.scheme == 'http' and not (fixture and host == 'localhost')) or
            (origin and parsed.path not in ('', '/')) or
            (not origin and (not parsed.path.startswith('/') or parsed.path.startswith('//')))):
        raise SiteContractError("Invalid or unsupported site contract URL")
    base = f'{parsed.scheme}://{parsed.netloc}'
    if origin and value != base:
        raise SiteContractError("Origin must be exact and canonical")
    return base, host


def _safe_read(path: Path) -> object:
    # Pin every parent by descriptor before opening its child. This protects
    # against pathname swaps, not against writers with the manager's own UID.
    absolute = Path(os.path.abspath(path))
    with ExitStack() as stack:
        parent_fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        stack.callback(os.close, parent_fd)
        private_ancestor = False
        for component in ('/', *absolute.parent.parts[1:]):
            if component != '/':
                parent_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                    dir_fd=parent_fd)
                stack.callback(os.close, parent_fd)
            info = os.fstat(parent_fd)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid()) or
                    (info.st_mode & 0o022 and not private_ancestor)):
                raise SiteContractError("Site contract path is not manager-controlled")
            if info.st_uid == os.geteuid() and not info.st_mode & 0o077:
                private_ancestor = True
        if not private_ancestor or os.fstat(parent_fd).st_mode & 0o022:
            raise SiteContractError("Site contract path is not manager-controlled")
        fd = os.open(absolute.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=parent_fd)
        stack.callback(os.close, fd)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.geteuid()) or
                info.st_mode & 0o077 or info.st_size > 16384):
            raise SiteContractError("Site contract file is not manager-controlled")
        with os.fdopen(os.dup(fd), 'r', encoding='utf-8') as stream:
            return json.load(stream)


def load_site_contract(path: str | Path, *, program: str, auth_domain: str,
                       account_alias: str, origin: str) -> SiteContract:
    """Load a reviewed file and bind it to an exact requested pool and origin.

    Callers must not accept the path or requested identity from a browser/agent.
    Errors are safe to show publicly and contain no raw file content or path.
    """
    try:
        data = _object(_safe_read(Path(path)), {
            'program', 'auth_domain', 'account_alias', 'allowed_origins',
            'check', 'local_storage_keys', 'cookie_selector', 'disposable_fixture',
        })
        fixture = data['disposable_fixture'] is True
        if type(data['disposable_fixture']) is not bool:
            raise SiteContractError("Invalid fixture designation")
        pool = (_text(data['program']), _domain(data['auth_domain']), _text(data['account_alias']))
        requested = (_text(program), _domain(auth_domain), _text(account_alias))
        if pool != requested:
            raise SiteContractError("Site contract pool mismatch")
        if fixture and pool != ('fixture', 'fixture.invalid', 'anon'):
            raise SiteContractError("Fixture exception is limited to disposable fixture pool")
        origins = data['allowed_origins']
        if type(origins) is not list or not origins or len(origins) > 16:
            raise SiteContractError("Invalid allowed origins")
        parsed_origins = [_url(item, origin=True, fixture=fixture) for item in origins]
        if len({base for base, _ in parsed_origins}) != len(origins):
            raise SiteContractError("Duplicate allowed origin")
        requested_origin, _ = _url(origin, origin=True, fixture=fixture)
        if requested_origin not in [base for base, _ in parsed_origins]:
            raise SiteContractError("Site contract origin mismatch")
        check = _object(data['check'], {'url', 'method', 'principal_selector', 'expected_principal'})
        if check['method'] != 'GET':
            raise SiteContractError("Unsupported login check method")
        check_base, _ = _url(check['url'], fixture=fixture)
        if check_base != requested_origin:
            raise SiteContractError("Login check must be same-origin")
        selector = _text(check['principal_selector'])
        if not re.fullmatch(r'#[A-Za-z][A-Za-z0-9_-]*|\[data-testid="[A-Za-z][A-Za-z0-9_-]*"\]', selector):
            raise SiteContractError("Unsupported principal selector")
        expected = _text(check['expected_principal'])
        keys = data['local_storage_keys']
        if (type(keys) is not list or not keys or len(keys) > 16 or
                any(not isinstance(k, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.:-]*', k) for k in keys) or
                len(set(keys)) != len(keys)):
            raise SiteContractError("Invalid localStorage key selection")
        cookie = _object(data['cookie_selector'], {'name', 'domain', 'path'})
        name = _text(cookie['name'])
        domain = _domain(cookie['domain'])
        cookie_path = _text(cookie['path'])
        if (not re.fullmatch(r'(?:[A-Za-z]|__Host-)[A-Za-z0-9_-]*', name) or
                domain != dict(parsed_origins)[requested_origin] or
                (not fixture and ('.' not in domain or domain in _SECOND_LEVEL_SUFFIXES or
                                  all(part.isdigit() for part in domain.split('.')))) or
                not cookie_path.startswith('/') or cookie_path.startswith('//')):
            raise SiteContractError("Invalid cookie selector")
        return SiteContract(*pool, tuple(base for base, _ in parsed_origins),
                            check['url'], selector, expected, tuple(keys), name, domain, cookie_path)
    except SiteContractError:
        raise
    except (OSError, ValueError, TypeError, UnicodeError) as exc:
        raise SiteContractError("Site contract unavailable or malformed") from exc


def verify_cookie_scope(contract: SiteContract, *, browser_domain: str,
                        host_only: bool | None, secure: bool | None = False,
                        browser_path: str | None = None) -> None:
    """Gate a selected cookie on actual browser scope metadata before transfer.

    The caller must obtain authoritative host-only/Domain-attribute metadata
    from its browser source; do not infer it from the selector or a leading dot.
    When CDP omits host-only metadata, only a browser-enforced __Host- prefix
    with Secure and Path=/ proves the host-only property. Never infer it from
    domain spelling or the contract alone.
    """
    prefix_proof = (host_only is None and contract.cookie_name.startswith('__Host-')
                    and secure is True and browser_path == '/' and contract.cookie_path == '/')
    if (not (host_only is True or prefix_proof) or
            type(browser_domain) is not str or browser_domain != contract.cookie_domain):
        raise SiteContractError("Browser cookie scope is not host-only for selected domain")


def verify_check_response(contract: SiteContract, *, response_url: str,
                          status: int, redirected: bool, principal: str) -> None:
    """Refuse any redirect, unexpected URL/status, or nonmatching principal.

    This is not a network client: configure the actual request to NOT follow
    redirects, then pass its response and extracted selector text here.
    """
    if (type(redirected) is not bool or redirected or type(status) is not int or
            status != 200 or response_url != contract.check_url or
            type(principal) is not str or principal != contract.expected_principal):
        raise SiteContractError("Login check did not attest the expected principal")
