#
#   Copyright (c) 2018 One Identity
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
import os
import pytest

from pyrad.dictionary import Dictionary
from pyrad.packet import AccessAccept, AccessChallenge, AccessReject, AuthPacket
from tempfile import TemporaryDirectory
from ...plugin import Plugin


class DummyRadiusClient:
    QUESTION = '6 * 9 = ?'

    @classmethod
    def from_config(cls, *args, **kwargs):
        return cls()

    def authenticate(self, username, password, state):
        kwargs, other = {
            ('the_username', 'the_password', None): ({'code': AccessAccept}, {}),
            ('the_username', 'not_the_password', None): ({'code': AccessReject}, {}),
            ('not_the_username', 'some_password', None): ({'code': AccessReject}, {}),
            ('the_challenger', 'their_password', None): (
                {
                    'code': AccessChallenge,
                    'dict': Dictionary('lib/tests/assets/dictionary'),
                },
                {
                    'Reply-Message': self.QUESTION,
                    'State': b'the_state',
                    'Prompt': 'No-Echo',
                }
            ),
            ('the_challenger', '42', 'the_state'): ({'code': AccessAccept}, {}),
        }[(username, password, state)]
        packet = AuthPacket(**kwargs)
        for k, v in other.items():
            packet[k] = v
        return packet


class AcceptAllRadiusClient:
    @classmethod
    def from_config(cls, *args, **kwargs):
        return cls()

    def authenticate(self, username, password, state):
        return AuthPacket(code=AccessAccept)


@pytest.fixture(autouse=True)
def dummy_radius_client(monkeypatch):
    monkeypatch.setattr('lib.plugin.RadiusClient', DummyRadiusClient)


@pytest.fixture(autouse=True)
def fake_plugin_context(monkeypatch):
    with TemporaryDirectory(prefix='sps-radius-plugin-test-', suffix='-persistent_plugin_state') as persistent_dir:
        with TemporaryDirectory(prefix='sps-radius-plugin-test-', suffix='-ephemeral_plugin_state') as ephemeral_dir:
            monkeypatch.setitem(os.environ, 'SCB_PLUGIN_STATE_DIRECTORY', persistent_dir)
            monkeypatch.setitem(os.environ, 'EPHEMERAL_PLUGIN_STATE_DIRECTORY', ephemeral_dir)
            yield


def provide_get_radius_username_cases():
    yield {
        'params': {
            'gateway_user': 'gwuser',
            'key_value_pairs': {},
            'target_username': 'tguser',
        },
        'expected': 'gwuser'
    }
    yield {
        'params': {
            'gateway_user': None,
            'key_value_pairs': {},
            'target_username': 'tguser',
        },
        'expected': 'tguser'
    }
    yield {
        'params': {
            'gateway_user': None,
            'key_value_pairs': {},
            'target_username': None,
        },
        'expected': None
    }
    yield {
        'params': {
            'gateway_user': 'gwuser',
            'key_value_pairs': {'radius_username': 'radiususer', 'ru': 'ruuser'},
            'target_username': 'tguser',
        },
        'expected': 'radiususer'
    }
    yield {
        'params': {
            'gateway_user': 'gwuser',
            'key_value_pairs': {'ru': 'ruuser'},
            'target_username': 'tguser',
        },
        'expected': 'ruuser'
    }


@pytest.mark.parametrize('tc', provide_get_radius_username_cases())
def test_get_radius_username(tc):
    def check_tc(params, expected):
        config = ''
        plugin = Plugin(config)
        plugin.authenticate(**(enrich_params_with_mandatory_keys(params)))
        print(plugin.cookie)
        assert plugin.cookie.get('mfa_identity') == expected

    check_tc(**tc)


@pytest.mark.parametrize('tc', provide_get_radius_username_cases())
def test_authenticate_vs_username(tc):
    def check_tc(params, expected):
        config = ''
        plugin = Plugin(config)
        result = plugin.authenticate(**enrich_params_with_mandatory_keys(params))
        if expected is None:
            assert result['verdict'] == 'DENY'
        else:
            assert result['verdict'] == 'NEEDINFO'
            assert result['question'][0] == 'otp'

    check_tc(**tc)


def enrich_params_with_mandatory_keys(params):
    connection_parameters = {
        'session_id': '',
        'protocol': '',
        'connection_name': '',
        'client_ip': '',
        'client_port': '',
        'gateway_user': '',
        'target_username': '',
        'key_value_pairs': {},
        'cookie': {},
        'session_cookie': {}
    }
    connection_parameters.update(params)
    return connection_parameters


def provide_get_radius_password_cases():
    yield {
        'params': {
            'key_value_pairs': {}
        },
        'expected': None
    }
    yield {
        'params': {
            'key_value_pairs': {}
        },
        'expected': None
    }
    yield {
        'params': {
            'key_value_pairs': {'rp': 'rppass'}
        },
        'expected': 'rppass'
    }
    yield {
        'params': {
            'key_value_pairs': {'radius_password': 'radiuspass', 'rp': 'rppass'}
        },
        'expected': 'radiuspass'
    }


@pytest.mark.parametrize('tc', provide_get_radius_password_cases())
def test_authenticate_vs_password(tc, monkeypatch):
    monkeypatch.setattr('lib.plugin.RadiusClient', AcceptAllRadiusClient)

    def check_tc(params, expected):
        config = ''
        plugin = Plugin(config)
        kv_pairs = params['key_value_pairs']
        assert 'radius_username' not in kv_pairs
        kv_pairs['radius_username'] = 'radius_username'
        result = plugin.authenticate(**enrich_params_with_mandatory_keys(
            dict(client_ip='1.2.3.4', gateway_user='gwuser', key_value_pairs=kv_pairs)))
        if expected is None:
            assert result['verdict'] == 'NEEDINFO'
            assert result['question'][0] == 'otp'
        else:
            assert result['verdict'] == 'ACCEPT'

    check_tc(**tc)


def test_authenticate_with_radius_password():
    plugin = Plugin("")
    result = plugin.authenticate(**enrich_params_with_mandatory_keys(
                                 dict(cookie={}, client_ip='1.2.3.4', gateway_user='the_username',
                                      key_value_pairs={'radius_password': 'the_password'})))
    assert result['verdict'] == 'ACCEPT'


def test_authenticate_with_only_target_user():
    plugin = Plugin("")
    result = plugin.authenticate(**enrich_params_with_mandatory_keys(
        dict(cookie={}, client_ip='1.2.3.4', target_username='the_username',
             key_value_pairs={'radius_password': 'the_password'})))
    assert result['verdict'] == 'ACCEPT'
    assert result['gateway_user'] == 'the_username'
    assert result['gateway_groups'] == ()


def test_authenticate_with_only_radius_user():
    plugin = Plugin("")
    result = plugin.authenticate(
        **enrich_params_with_mandatory_keys(
            dict(cookie={}, client_ip='1.2.3.4',
                 key_value_pairs={
                     'radius_password': 'the_password',
                     'radius_username': 'the_username',
                }
            )
        )
    )
    assert result['verdict'] == 'ACCEPT'
    assert result['gateway_user'] == 'the_username'
    assert result['gateway_groups'] == ()


def test_authenticate_with_bad_gateway_user():
    plugin = Plugin("")
    result = plugin.authenticate(**enrich_params_with_mandatory_keys(
                                 dict(cookie={}, client_ip='1.2.3.4', gateway_user='not_the_username',
                                      key_value_pairs={'rp': 'some_password'})))
    assert result['verdict'] == 'DENY'


def test_authenticate_with_bad_radius_password():
    plugin = Plugin("")
    result = plugin.authenticate(**enrich_params_with_mandatory_keys(
                                 dict(cookie={}, client_ip='1.2.3.4', gateway_user='the_username',
                                      key_value_pairs={'rp': 'not_the_password'})))
    assert result['verdict'] == 'DENY'


def test_authenticate_with_challenge():
    plugin = Plugin("")
    result = plugin.authenticate(**enrich_params_with_mandatory_keys(
                                 dict(cookie={}, client_ip='1.2.3.4', gateway_user='the_challenger',
                                      key_value_pairs={'rp': 'their_password'})))
    assert result['verdict'] == 'NEEDINFO'
    assert result['question'] == ('radius_password', DummyRadiusClient.QUESTION, True)
    assert 'state' in result['cookie']
    plugin2 = Plugin("")
    result = plugin2.authenticate(**enrich_params_with_mandatory_keys(
                                 dict(cookie=result['cookie'], client_ip='1.2.3.4',
                                      gateway_user='the_challenger',
                                      key_value_pairs={'radius_password': '42'})))
    assert result['verdict'] == 'ACCEPT'
