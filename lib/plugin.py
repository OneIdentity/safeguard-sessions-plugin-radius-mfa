#
#   Copyright (c) 2019 One Identity
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
from base64 import b64encode, b64decode
from re import sub
from socket import error as socket_error

from safeguard.sessions.plugin import AAPlugin, AAResponse
from pyrad.packet import AccessReject, AccessAccept, AccessChallenge

from .radius import RadiusClient


class Plugin(AAPlugin):
    def __init__(self, configuration):
        super().__init__(configuration)

    def _extract_username(self):
        return (
            self.connection.key_value_pairs.get("radius_username")
            or self.connection.key_value_pairs.get("ru")
            or super()._extract_username()
        )

    def do_authenticate(self):
        radius_username = self.mfa_identity
        self.logger.info("RADIUS username is '{}'".format(radius_username))

        try:
            radcli = RadiusClient.from_config(self.plugin_configuration)
        except Exception as ex:
            self.logger.error(
                "Error creating RADIUS client instance.\n" "An exception of type %s occured. Arguments:\n" "%s",
                type(ex).__name__,
                ex.args,
            )
            return AAResponse.deny()

        try:
            prev_state = self.cookie.get("state")
            prev_state = None if prev_state is None else b64decode(prev_state.encode("latin-1")).decode("latin-1")
            radrep = radcli.authenticate(username=radius_username, password=self.mfa_password, state=prev_state)
        except TimeoutError:
            self.logger.error("Network timeout while talking to RADIUS server.")
            return AAResponse.deny()
        except socket_error as ex:
            self.logger.error("Network error while talking to RADIUS server: %s", ex)
            return AAResponse.deny()
        except Exception as ex:
            self.logger.error("An exception of type %s occured. Arguments:\n%s", type(ex).__name__, ex.args)
            self.logger.debug("Exception details follow.", exc_info=ex)
            return AAResponse.deny()

        if radrep.code == AccessAccept:
            self.logger.info("RADIUS authentication was successful!")
            return AAResponse.accept()

        elif radrep.code == AccessReject:
            self.logger.info("RADIUS authentication was rejected!")
            return AAResponse.deny()
        elif radrep.code == AccessChallenge:
            self.logger.info("RADIUS challenge received")
            challenge = sub("\x00", "", "".join(radrep["Reply-Message"][0]))
            echo_off = "Prompt" in radrep and radrep["Prompt"][0] == "No-Echo"
            state = b64encode(radrep["State"][0]).decode("latin-1")
            return AAResponse.need_info(challenge, "radius_password", echo_off).with_cookie(dict(state=state))
        else:
            self.logger.error("Unhandled RADIUS reply code: %s", radrep.code)
            return AAResponse.deny()

    def _extract_mfa_password(self):
        return (
            self.connection.key_value_pairs.get("radius_password")
            or self.connection.key_value_pairs.get("rp")
            or super()._extract_mfa_password()
        )
