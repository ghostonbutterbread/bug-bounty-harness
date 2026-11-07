"""Offline contract boundary tests; no browser state or live account required."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agents.browser_auth_site_contract import (
    SiteContractError, load_site_contract, verify_check_response, verify_cookie_scope,
    exact_origin_cookie_params,
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

    def test_json_principal_key_accepts_exact_origin_and_expected_principal(self):
        self.data.update(program='sample', auth_domain='example.org', account_alias='owned',
                         disposable_fixture=False, allowed_origins=['https://app.example.org'],
                         state_mode='exact-origin')
        del self.data['local_storage_keys']
        del self.data['cookie_selector']
        self.data['check'] = {'url': 'https://app.example.org/1/member/me', 'method': 'GET',
                              'principal_json_key': 'id', 'expected_principal': 'owned-id'}
        contract = self.load(program='sample', auth_domain='example.org',
                             account_alias='owned', origin='https://app.example.org')
        self.assertIsNone(contract.principal_selector)
        self.assertEqual(contract.principal_json_key, 'id')
        verify_check_response(contract, response_url=contract.check_url,
                              status=200, redirected=False, principal='owned-id')
        with self.assertRaises(SiteContractError):
            verify_check_response(contract, response_url=contract.check_url,
                                  status=200, redirected=False, principal='other-id')

    def test_json_principal_key_refuses_invalid_schema_and_untrusted_values(self):
        self.data['check'] = {'url': 'http://localhost:8765/me', 'method': 'GET',
                              'principal_json_key': 'id', 'expected_principal': 'anon'}
        for label, change in (
            ('both modes', lambda d: d.update(principal_selector='#identity')),
            ('neither mode', lambda d: d.pop('principal_json_key')),
            ('nested key', lambda d: d.update(principal_json_key='account.id')),
            ('script key', lambda d: d.update(principal_json_key='id\"); alert(1)')),
            ('empty key', lambda d: d.update(principal_json_key='')),
            ('nonstring key', lambda d: d.update(principal_json_key=['id'])),
            ('nonstring principal', lambda d: d.update(expected_principal=7)),
            ('wrong method', lambda d: d.update(method='POST')),
            ('query URL', lambda d: d.update(url='http://localhost:8765/me?secret=raw-value')),
            ('other origin', lambda d: d.update(url='https://else.example.org/me')),
            ('extra key', lambda d: d.update(script='raw-value')),
        ):
            with self.subTest(label=label):
                data = json.loads(json.dumps(self.data))
                change(data['check'])
                self.data = data
                with self.assertRaises(SiteContractError) as caught:
                    self.load()
                self.assertNotIn('raw-value', str(caught.exception))
                self.assertNotIn('alert(1)', str(caught.exception))
                self.data['check'] = {'url': 'http://localhost:8765/me', 'method': 'GET',
                                      'principal_json_key': 'id', 'expected_principal': 'anon'}

    def test_exact_origin_mode_needs_no_cookie_selector_or_storage_keys(self):
        self.data.update(program='sample', auth_domain='example.org',
                         account_alias='owned', disposable_fixture=False,
                         allowed_origins=['https://app.example.org'],
                         state_mode='exact-origin')
        self.data['check'].update(url='https://app.example.org/me', expected_principal='owned')
        del self.data['cookie_selector']
        del self.data['local_storage_keys']
        contract = self.load(program='sample', auth_domain='example.org',
                             account_alias='owned', origin='https://app.example.org')
        self.assertEqual(contract.state_mode, 'exact-origin')
        self.assertEqual(contract.local_storage_keys, ())
        self.data['cookie_selector'] = {'name': '__Host-token', 'domain': 'app.example.org', 'path': '/'}
        with self.assertRaises(SiteContractError):
            self.load(program='sample', auth_domain='example.org',
                      account_alias='owned', origin='https://app.example.org')

    def test_exact_origin_cookie_params_preserve_host_only_and_parent_domain(self):
        cookies = [
            {'name': '__Host-session', 'value': 'private', 'domain': 'auth.example.test',
             'path': '/', 'secure': True, 'httpOnly': True, 'sameSite': 'Lax',
             'session': True, 'priority': 'High', 'size': 42},
            {'name': 'shared', 'value': 'parent', 'domain': '.example.test',
             'path': '/account', 'secure': True, 'httpOnly': True, 'sameSite': 'Strict',
             'session': False, 'expires': 2000000000, 'priority': 'Medium', 'size': 30},
            {'name': 'other', 'value': 'leave', 'domain': '.else.test', 'path': '/'},
        ]
        params = exact_origin_cookie_params(cookies, 'auth.example.test', 'https://auth.example.test')
        self.assertEqual(len(params), 2)
        self.assertNotIn('domain', params[0])
        self.assertEqual(params[0]['url'], 'https://auth.example.test/')
        self.assertEqual(params[0]['sameSite'], 'Lax')
        self.assertNotIn('expires', params[0])
        self.assertEqual(params[1]['domain'], '.example.test')
        self.assertEqual(params[1]['path'], '/account')
        self.assertEqual(params[1]['expires'], 2000000000)
        self.assertNotIn('size', params[1])

    def test_exact_origin_unprefixed_exact_host_narrows_to_url_scope(self):
        for spelling, metadata in (('auth.example.test', {}),
                                   ('auth.example.test', {'hostOnly': False}),
                                   ('.auth.example.test', {})):
            with self.subTest(spelling=spelling, metadata=metadata):
                cookie = {'name': 'session', 'value': 'private', 'domain': spelling,
                          'path': '/account', 'secure': True, 'httpOnly': True,
                          'sameSite': 'Strict', 'session': False, 'expires': 2000000000,
                          **metadata}
                params = exact_origin_cookie_params([cookie], 'auth.example.test',
                                                     'https://auth.example.test')
                self.assertEqual(params, [{
                    'name': 'session', 'value': 'private', 'url': 'https://auth.example.test/account',
                    'path': '/account', 'secure': True, 'httpOnly': True,
                    'sameSite': 'Strict', 'expires': 2000000000,
                }])

    def test_exact_origin_cookie_params_refuse_partition_or_invalid_host(self):
        cookie = {'name': '__Host-session', 'value': 'secret', 'domain': 'auth.example.test',
                  'path': '/', 'secure': True, 'httpOnly': True, 'session': True}
        for alteration in ({'domain': '.auth.example.test'},
                           {'domain': '.example.test', 'hostOnly': True},
                           {'domain': 'example.test', 'name': 'plain'},
                           {'domain': 'auth.example.test', 'hostOnly': False},
                           {'partitionKey': {'topLevelSite': 'https://example.test'}},
                           {'sameParty': True}, {'sourceScheme': 'Unknown'},
                           {'futureCookieConstraint': 'unrepresented'}):
            with self.subTest(alteration=alteration), self.assertRaises(SiteContractError) as caught:
                exact_origin_cookie_params([{**cookie, **alteration}],
                                           'auth.example.test', 'https://auth.example.test')
            self.assertNotIn('secret', str(caught.exception))

    def test_exact_origin_refuses_name_path_collision_across_source_scopes(self):
        base = {'name': 'session', 'value': 'private', 'path': '/', 'secure': True,
                'httpOnly': True, 'session': True}
        for scopes in ((('auth.example.test', None), ('.auth.example.test', None)),
                       (('auth.example.test', True), ('.example.test', False)),
                       (('auth.example.test', None), ('auth.example.test', None))):
            with self.subTest(scopes=scopes), self.assertRaises(SiteContractError):
                exact_origin_cookie_params([{
                    **base, 'domain': domain, **({'hostOnly': scope} if scope is not None else {})
                } for domain, scope in scopes],
                                           'auth.example.test', 'https://auth.example.test')

    def test_exact_origin_cookie_payload_is_bounded(self):
        cookie = {'name': '__Host-session', 'value': 'x' * 131073,
                  'domain': 'auth.example.test', 'path': '/', 'secure': True,
                  'httpOnly': True, 'session': True}
        with self.assertRaises(SiteContractError):
            exact_origin_cookie_params([cookie], 'auth.example.test', 'https://auth.example.test')

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
