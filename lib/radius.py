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
from pyrad.client import Client, Timeout
from pyrad.dictionary import Dictionary
from pyrad.packet import AccessRequest, AuthPacket, md5_constructor


class _SCBAuthPacket(AuthPacket):
    def __init__(self, code=AccessRequest, id=None, secret="", authenticator=None, **attributes):
        super().__init__(code, id, secret, authenticator, **attributes)

    def ChapDigest(self, password):
        if self.authenticator is None:
            self.authenticator = self.CreateAuthenticator()

        id_str = chr(self.id).encode('latin-1')
        md5 = md5_constructor()
        md5.update(id_str)
        md5.update(password.encode('latin-1'))
        md5.update(self.authenticator)
        digest = md5.digest()

        return id_str + digest


class RadiusClient:
    def __init__(self, client, auth_type):
        self.__client = client
        self.__auth_type = auth_type

    @classmethod
    def from_config(cls, plugin_config, section='radius'):
        secret = plugin_config.get(section, 'secret')
        client = Client(
            server=plugin_config.get(section, 'server', required=True),
            authport=plugin_config.getint(section, 'port', 1812),
            secret=secret.encode('ascii') if secret else None,
            dict=Dictionary(plugin_config.get(section, 'dictionary_path', "/usr/share/zorp/dictionary")))
        client.retries = plugin_config.getint(section, 'conn_retries', 3)
        client.timeout = plugin_config.getint(section, 'conn_timeout', 5)
        auth_type = plugin_config.getienum(section, 'auth_type', ('pap', 'chap'), default='pap')

        return cls(client, auth_type)

    def authenticate(self, username, password, state=None):
        packet = self.__createAuthenticationPacket(username=username, password=password, state=state)
        try:
            return self.__client.SendPacket(packet)
        except Timeout as err:
            raise TimeoutError from err

    def __createAuthenticationPacket(self, username, password, state):
        req = _SCBAuthPacket(secret=self.__client.secret, dict=self.__client.dict)

        req.AddAttribute(key="User-Name", value=username)  # attribute type=1

        if self.__auth_type == 'pap':  # attribute type=2
            req.AddAttribute(key="User-Password", value=req.PwCrypt(password))
        elif self.__auth_type == 'chap':
            req.AddAttribute(key="CHAP-Password", value=req.ChapDigest(password))

        req.AddAttribute(key="Service-Type", value="Login-User")  # attribute type=6

        if state is not None:
            req.AddAttribute(key="State", value=state.encode('latin-1'))  # attribute type=24

        return req
