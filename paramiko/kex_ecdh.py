# Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""
Elliptic Curve Diffie-Hellman (ECDH) key agreement
Base ECDH using 256 bit eliptic curve
384 and 521 size classes can inherit this one
https://tools.ietf.org/html/rfc5656
"""

import os
from hashlib import sha256
from ecdsa import SigningKey, VerifyingKey, der, curves

from paramiko import util
from paramiko.common import max_byte, zero_byte
from paramiko.message import Message
from paramiko.py3compat import byte_chr, long, byte_mask
from paramiko.ssh_exception import SSHException


_MSG_KEX_ECDH_INIT, _MSG_KEX_ECDH_REPLY = range(30, 32)
c_MSG_KEX_ECDH_INIT, c_MSG_KEX_ECDH_REPLY = [byte_chr(c) for c in range(30, 32)]

b7fffffffffffffff = byte_chr(0x7f) + max_byte * 7
b0000000000000000 = zero_byte * 8


###### https://tools.ietf.org/html/rfc5656#page-6

class KexECDH256(object):

    name = 'ecdh-sha2-nistp256'
    hash_algo = sha256
    curve = curves.NIST256p

    def __init__(self, transport):
        self.transport = transport
        self.verifying_key = None
        self.signing_key = None

    def start_kex(self):
        self.signing_key = SigningKey.generate(curve=curve)
        self.verifying_key = sk.get_verifying_key()
 
        if self.transport.server_mode:
            self.transport._expect_packet(_MSG_KEX_ECDH_INIT)
            return

        m = Message()
        m.add_byte(c_MSG_KEX_ECDH_INIT)
        m.add_string(self.verifying_key.to_string())
        self.transport._send_message(m)
        self.transport._expect_packet(_MSG_KEX_ECDH_REPLY)

    def parse_next(self, ptype, m):
        if self.transport.server_mode and (ptype == _MSG_KEX_ECDH_INIT):
            return self._parse_kex_ecdh_init(m)
        elif not self.transport.server_mode and (ptype == _MSG_KEX_ECDH_REPLY):
            return self._parse_kex_ecdh_reply(m)
        raise SSHException('KexECDH asked to handle packet type %d' % ptype)

    ###  internals...

    def _parse_kex_ecdh_reply(self, m):
        # client mode
        host_key = m.get_string()
        self.Q_S = m.get_string()
        sig = m.get_binary()
        K = pow(self.f, self.x, self.P)
        # okay, build up the hash H of (V_C || V_S || I_C || I_S || K_S || e || f || K)
        hm = Message()
        hm.add(self.transport.local_version, self.transport.remote_version,
               self.transport.local_kex_init, self.transport.remote_kex_init)
        hm.add_string(host_key)
        hm.add_mpint(self.e)
        hm.add_mpint(self.f)
        hm.add_mpint(K)
        self.transport._set_K_H(K, sha1(hm.asbytes()).digest())
        self.transport._verify_key(host_key, sig)
        self.transport._activate_outbound()

    def _parse_kex_ecdh_init(self, m):
        # server mode
        self.e = m.get_mpint()
        if (self.e < 1) or (self.e > self.P - 1):
            raise SSHException('Client kex "e" is out of range')
        K = pow(self.e, self.x, self.P)
        key = self.transport.get_server_key().asbytes()
        # okay, build up the hash H of (V_C || V_S || I_C || I_S || K_S || e || f || K)
        hm = Message()
        hm.add(self.transport.remote_version, self.transport.local_version,
               self.transport.remote_kex_init, self.transport.local_kex_init)
        hm.add_string(key)
        hm.add_mpint(self.e)
        hm.add_mpint(self.f)
        hm.add_mpint(K)
        H = sha1(hm.asbytes()).digest()
        self.transport._set_K_H(K, H)
        # sign it
        sig = self.transport.get_server_key().sign_ssh_data(H)
        # send reply
        m = Message()
        m.add_byte(c_MSG_KEXDH_REPLY)
        m.add_string(key)
        m.add_mpint(self.f)
        m.add_string(sig)
        self.transport._send_message(m)
        self.transport._activate_outbound()

