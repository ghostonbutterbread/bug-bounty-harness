"""Offline contract boundary tests; no browser state or live account required."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agents.browser_auth_site_contract import (
    SiteContractError, load_site_contract, verify_check_response, verify_cookie_scope,
)


FIXTURE = {
    'program': 'fixture', 'auth_domain': 'fixture.invalid', 'account_alias': 'anon',
    'disposable_fixture': True,
    'allowed_origins': ['http://localhost:8765'],
    'check': {'url': 'http://localhost:8765/me', 'method': 'GET',
              'principal_selector': '[data-testid="account-name"]', 'expected_principal': 'anon'},
    'local_storage_keys': ['fixture_session'],
    'cookie_selector': {'name': 'fixture_cookie', 'domain': 'localhost', 'path': '/'},
}

def write_fixture_contract(directory, origin):
    data = json.loads(json.dumps(FIXTURE))
    data['allowed_origins'] = [origin]
    data['check']['url'] = origin + '/me'
    data['local_storage_keys'] = ['fixture-credential']
    data['cookie_selector']['name'] = '__Host-session'
    path = directory / 'fixture-site-contract.json'
    path.write_text(json.dumps(data))
    path.chmod(0o600)


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ['TMPDIR'])
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'contract.json'
        self.data = json.loads(json.dumps(FIXTURE))

    def load(self, **kwargs):
        self.path.write_text(json.dumps(self.data))
        self.path.chmod(0o600)
        return load_site_contract(self.path, program=kwargs.get('program', 'fixture'),
                                  auth_domain=kwargs.get('auth_domain', 'fixture.invalid'),
                                  account_alias=kwargs.get('account_alias', 'anon'),
                                  origin=kwargs.get('origin', 'http://localhost:8765'))

    def test_exact_pool_origin_and_attested_principal(self):
        contract = self.load()
        verify_check_response(contract, response_url=contract.check_url,
                              status=200, redirected=False, principal='anon')
        for field, wrong in [('program', 'other'), ('auth_domain', 'else.invalid'),
                             ('account_alias', 'different'), ('origin', 'http://localhost:8766')]:
            with self.subTest(field=field), self.assertRaises(SiteContractError):
                self.load(**{field: wrong})
        for kwargs in [dict(principal='someone else'), dict(redirected=True),
                       dict(response_url='https://else.invalid/me'), dict(status=302)]:
            with self.subTest(kwargs=kwargs), self.assertRaises(SiteContractError):
                verify_check_response(contract, response_url=kwargs.get('response_url', contract.check_url),
                                      status=kwargs.get('status', 200), redirected=kwargs.get('redirected', False),
                                      principal=kwargs.get('principal', 'anon'))

    def test_https_reviewed_origin(self):
        self.data.update(program='sample', auth_domain='login.example.org',
                         account_alias='owned', disposable_fixture=False,
                         allowed_origins=['https://app.example.org'])
        self.data['check'].update(url='https://app.example.org/me', expected_principal='owned')
        self.data['cookie_selector']['domain'] = 'app.example.org'
        contract = self.load(program='sample', auth_domain='login.example.org',
                             account_alias='owned', origin='https://app.example.org')
        self.assertEqual(contract.allowed_origins, ('https://app.example.org',))

    def test_explicit_default_port_is_not_an_origin_alias(self):
        self.data['allowed_origins'] = ['https://app.example.org:443']
        self.data['check']['url'] = 'https://app.example.org:443/me'
        self.data['cookie_selector']['domain'] = 'app.example.org'
        with self.assertRaises(SiteContractError):
            self.load(origin='https://app.example.org:443')
        self.data['allowed_origins'] = ['https://app.example.org']
        self.data['check']['url'] = 'https://app.example.org/me'
        with self.assertRaises(SiteContractError):
            self.load(origin='https://app.example.org:443')
        self.data['check']['url'] = 'https://app.example.org:443/me'
        with self.assertRaises(SiteContractError):
            self.load(origin='https://app.example.org')
        self.data = json.loads(json.dumps(FIXTURE))
        self.data['allowed_origins'] = ['http://localhost:80']
        self.data['check']['url'] = 'http://localhost:80/me'
        with self.assertRaises(SiteContractError):
            self.load(origin='http://localhost:80')

    def test_production_cookie_hosts_need_registrable_dns_shape(self):
        self.data.update(program='sample', auth_domain='login.example.org',
                         account_alias='owned', disposable_fixture=False)
        for host in ('com', 'co.uk', 'com.au', 'github.io', '127.0.0.1', '2130706433'):
            with self.subTest(host=host):
                self.data['allowed_origins'] = [f'https://{host}']
                self.data['check']['url'] = f'https://{host}/me'
                self.data['cookie_selector']['domain'] = host
                with self.assertRaises(SiteContractError):
                    self.load(program='sample', auth_domain='login.example.org',
                              account_alias='owned', origin=f'https://{host}')
        self.data['allowed_origins'] = ['https://shop.example.co.uk']
        self.data['check']['url'] = 'https://shop.example.co.uk/me'
        self.data['cookie_selector']['domain'] = 'shop.example.co.uk'
        self.assertEqual(self.load(program='sample', auth_domain='login.example.org',
                                   account_alias='owned', origin='https://shop.example.co.uk').cookie_domain,
                         'shop.example.co.uk')

    def test_cookie_scope_requires_authoritative_host_only_metadata(self):
        contract = self.load()
        verify_cookie_scope(contract, browser_domain='localhost', host_only=True)
        for domain, host_only in [('localhost', False), ('.localhost', False),
                                  ('fixture.invalid', True), ('localhost', None),
                                  ('localhost', 1)]:
            with self.subTest(domain=domain, host_only=host_only), self.assertRaises(SiteContractError):
                verify_cookie_scope(contract, browser_domain=domain, host_only=host_only)
        self.data['cookie_selector']['name'] = '__Host-session'
        contract = self.load()
        verify_cookie_scope(contract, browser_domain='localhost', host_only=None,
                            secure=True, browser_path='/')
        for secure, path in ((False, '/'), (True, '/nested'), (None, '/')):
            with self.assertRaises(SiteContractError):
                verify_cookie_scope(contract, browser_domain='localhost', host_only=None,
                                    secure=secure, browser_path=path)

    def test_same_name_domain_attribute_cookie_is_not_host_only(self):
        # Domain=app.example.org shares the host's spelling and cookie name,
        # but also reaches subdomains. A name/domain selector cannot prove scope.
        self.data.update(program='sample', auth_domain='login.example.org',
                         account_alias='owned', disposable_fixture=False,
                         allowed_origins=['https://app.example.org'])
        self.data['check'].update(url='https://app.example.org/me', expected_principal='owned')
        self.data['cookie_selector'].update(name='session', domain='app.example.org')
        contract = self.load(program='sample', auth_domain='login.example.org',
                             account_alias='owned', origin='https://app.example.org')
        verify_cookie_scope(contract, browser_domain='app.example.org', host_only=True, browser_path='/')
        with self.assertRaises(SiteContractError):
            verify_cookie_scope(contract, browser_domain='app.example.org',
                                host_only=False, browser_path='/')
        # A Domain=.example.org cookie is broader again, regardless of its
        # identical name and path; spelling alone is not authoritative metadata.
        with self.assertRaises(SiteContractError):
            verify_cookie_scope(contract, browser_domain='.example.org',
                                host_only=False, browser_path='/')

    def test_http_exception_only_for_disposable_fixture(self):
        self.data['disposable_fixture'] = False
        with self.assertRaises(SiteContractError):
            self.load()
        self.data['disposable_fixture'] = True
        self.data['program'] = 'real'
        with self.assertRaises(SiteContractError):
            self.load(program='real')
        self.data['program'] = 'fixture'
        self.data['allowed_origins'] = ['http://example.org']
        with self.assertRaises(SiteContractError):
            self.load(origin='http://example.org')

    def test_malformed_and_unsupported_state(self):
        alterations = [
            ('extra', lambda d: d.update(script='return localStorage')),
            ('wildcard', lambda d: d.update(auth_domain='*.invalid')),
            ('origin wildcard', lambda d: d.update(allowed_origins=['https://*.invalid'])),
            ('redirect check', lambda d: d['check'].update(url='https://example.org/me')),
            ('query check', lambda d: d['check'].update(url='http://localhost:8765/me?token=secret')),
            ('script selector', lambda d: d['check'].update(principal_selector='() => alert(1)')),
            ('method', lambda d: d['check'].update(method='POST')),
            ('storage', lambda d: d.update(session_storage_keys=['session'])),
            ('missing keys', lambda d: d.update(local_storage_keys=[])),
            ('cookie domain', lambda d: d['cookie_selector'].update(domain='.localhost')),
        ]
        for label, alter in alterations:
            with self.subTest(label=label):
                self.data = json.loads(json.dumps(FIXTURE))
                alter(self.data)
                with self.assertRaises(SiteContractError) as caught:
                    self.load()
                self.assertNotIn('secret', str(caught.exception))
        self.path.write_text('{"secret": "password-value",')
        self.path.chmod(0o600)
        with self.assertRaises(SiteContractError) as caught:
            load_site_contract(self.path, program='fixture', auth_domain='fixture.invalid',
                               account_alias='anon', origin='http://localhost:8765')
        self.assertNotIn('password-value', str(caught.exception))

    def test_parent_swap_cannot_redirect_read_after_directory_open(self):
        parent = Path(self.temp.name) / 'reviewed'
        parent.mkdir(mode=0o700)
        self.path = parent / 'contract.json'
        self.path.write_text(json.dumps(FIXTURE))
        self.path.chmod(0o600)
        replacement = Path(self.temp.name) / 'replacement'
        replacement.mkdir(mode=0o700)
        evil = json.loads(json.dumps(FIXTURE))
        evil['check']['expected_principal'] = 'other'
        (replacement / 'contract.json').write_text(json.dumps(evil))
        (replacement / 'contract.json').chmod(0o600)
        real_open = os.open
        swapped = False

        def swap_before_file_open(path, flags, *args, **kwargs):
            nonlocal swapped
            if str(path).endswith('contract.json') and not swapped:
                swapped = True
                parent.rename(Path(self.temp.name) / 'moved')
                replacement.rename(parent)
            return real_open(path, flags, *args, **kwargs)

        with patch('agents.browser_auth_site_contract.os.open', side_effect=swap_before_file_open):
            contract = load_site_contract(self.path, program='fixture', auth_domain='fixture.invalid',
                                          account_alias='anon', origin='http://localhost:8765')
        self.assertTrue(swapped)
        self.assertEqual(contract.expected_principal, 'anon')

    def test_file_integrity(self):
        self.load()
        self.path.chmod(0o644)
        with self.assertRaises(SiteContractError):
            load_site_contract(self.path, program='fixture', auth_domain='fixture.invalid',
                               account_alias='anon', origin='http://localhost:8765')
        self.path.unlink()
        target = Path(self.temp.name) / 'target.json'
        target.write_text(json.dumps(FIXTURE))
        target.chmod(0o600)
        self.path.symlink_to(target)
        with self.assertRaises(SiteContractError):
            load_site_contract(self.path, program='fixture', auth_domain='fixture.invalid',
                               account_alias='anon', origin='http://localhost:8765')
        self.path.unlink()
        linked_dir = Path(self.temp.name) / 'linked'
        linked_dir.symlink_to(Path(self.temp.name), target_is_directory=True)
        self.path = linked_dir / 'target.json'
        with self.assertRaises(SiteContractError):
            load_site_contract(self.path, program='fixture', auth_domain='fixture.invalid',
                               account_alias='anon', origin='http://localhost:8765')
        child = Path(self.temp.name) / 'child'
        child.mkdir()
        child.chmod(0o777)
        self.path = child / 'contract.json'
        with self.assertRaises(SiteContractError):
            self.load()


if __name__ == '__main__':
    unittest.main()
