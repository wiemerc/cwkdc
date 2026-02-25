#!/usr/bin/env python3


import asyncio
import sys

from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser
from datetime import datetime, timezone

from impacket.krb5.asn1 import AS_REQ, KRB_ERROR, PrincipalName, seq_set
from impacket.krb5.constants import ApplicationTagNumbers, ErrorCodes, PrincipalNameType
from impacket.krb5.crypto import Key, _get_enctype_profile, get_random_bytes
from impacket.krb5.types import Principal
from loguru import logger
from pyasn1.codec.der import decoder, encoder


EXIT_OK = 0
EXIT_ERROR = 1

KRB_REALM = "CWTEST.LOCAL"
KRB_SNAME = "krbtgt"
KRB_KNOWN_PRINCIPALS = {
    "consti@CWTEST.LOCAL": "consti123",
    "krbtgt@CWTEST.LOCAL": "krbtgt123",
}


class KrbError:
    def __init__(self, code: ErrorCodes, text: str):
        self.code = code
        self.text = text

    def to_asn1(self) -> bytes:
        msg = KRB_ERROR()
        msg["pvno"] = 5
        msg["msg-type"] = ApplicationTagNumbers.KRB_ERROR.value
        now = datetime.now(timezone.utc)
        msg["stime"] = now.strftime("%Y%m%d%H%M%SZ")
        msg["susec"] = now.microsecond
        msg["realm"] = KRB_REALM
        msg["error-code"] = self.code.value
        msg["e-text"] = self.text
        seq_set(msg, "sname", Principal((KRB_SNAME, KRB_REALM), type=PrincipalNameType.NT_SRV_INST.value).components_to_asn1)
        return encoder.encode(msg)



# Relevant links:
# - https://www.youtube.com/watch?v=pzrtfRpPVM4
# - https://academy.hackthebox.com/module/74/section/701
# - https://datatracker.ietf.org/doc/html/rfc4120
# - https://kerberos.org/software/tutorial.html
class KerberosServer:
    def connection_made(self, transport):
        self.transport = transport


    def connection_lost(self, exc):
        pass


    def datagram_received(self, data, addr):
        logger.info(f"Message received from {addr}, {len(data)} bytes long")
        req, _ = decoder.decode(data, asn1Spec=AS_REQ())
        req_body = req["req-body"]
        cname = req_body["cname"]
        realm = str(req_body["realm"])
        cpn = str(cname["name-string"][0]) + "@" + realm
        sname = req_body["sname"]
        spn = str(sname["name-string"][0]) + "@" + str(sname["name-string"][1])
        enctype_to_use = req_body["etype"][0]
        logger.debug(f"Message is AS-REQ: UPN={cpn}, SPN={spn}")

        if cpn in KRB_KNOWN_PRINCIPALS:
            logger.info(f"Client principal '{cpn}' is known")
            up_key = self._create_principal_key(
                enctype=enctype_to_use,
                realm=realm,
                principal_name=cname,
                principal_passwd=KRB_KNOWN_PRINCIPALS[cpn],
            )
            logger.debug(
                f"Created key {up_key.contents} for principal '{cpn}' with encryption type {enctype_to_use} "
                f"(the first one offered by the client)"
            )
        else:
            logger.error(f"Client principal '{cpn}' is not known")
            resp = KrbError(ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN, f"User '{cpn}' is not known")
            self.transport.sendto(resp.to_asn1(), addr)
        if spn in KRB_KNOWN_PRINCIPALS:
            logger.info(f"Service principal '{spn}' is known")
            sp_key = self._create_principal_key(
                enctype=enctype_to_use,
                realm=str(sname["name-string"][1]),
                principal_name=sname,
                principal_passwd=KRB_KNOWN_PRINCIPALS[spn],
            )
            logger.debug(
                f"Created key {sp_key.contents} for principal '{spn}' with encryption type {enctype_to_use} "
                f"(the first one offered by the client)"
            )
        else:
            logger.error(f"Service principal '{spn}' is not known")
            resp = KrbError(ErrorCodes.KDC_ERR_S_PRINCIPAL_UNKNOWN, f"User '{spn}' is not known")
            self.transport.sendto(resp.to_asn1(), addr)
        # TODO: Create TGT
        # TODO: Create AS_REP message

        session_key = self._create_session_key(enctype_to_use)
        logger.debug(
            f"Created session key {session_key.contents} for encryption type {enctype_to_use} "
            f"(the first one offered by the client)"
        )


    def _create_session_key(self, enctype: int) -> Key:
        """
        Create a random session key for the specified encryption type
        """
        enctype_profile = _get_enctype_profile(enctype)
        seed = get_random_bytes(enctype_profile.seedsize)
        return enctype_profile.random_to_key(seed)


    def _create_principal_key(self, enctype: int, realm: str, principal_name: PrincipalName, principal_passwd: str) -> Key:
        """
        Create the key derived from the principal's password for the specified encryption type
        """
        enctype_profile = _get_enctype_profile(enctype)
        salt = realm + str(principal_name["name-string"][0])
        return enctype_profile.string_to_key(principal_passwd, salt, params=None)


async def main() -> int:
    parser = ArgumentParser(
        description="Proof-of-concept for a Kerberos server",
        formatter_class=ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--listen-addr", default="127.0.0.1", help="IP address to listen on")
    parser.add_argument("--listen-port", type=int, default=8888, help="Port to listen on")
    parser.add_argument("--verbose", "-v", action="store_true", help="Be verbose")
    args = parser.parse_args()

    logger.info("Starting server")
    loop = asyncio.get_running_loop()
    transport, server = await loop.create_datagram_endpoint(
        KerberosServer,
        local_addr=(args.listen_addr, args.listen_port),
    )
    try:
        await asyncio.Event().wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.info("Shutting down server")
        return EXIT_OK
    except Exception as e:
        if args.verbose:
            logger.exception("Error occurred:")
        else:
            logger.error(f"Error occurred: {e}")
        return EXIT_ERROR
    finally:
        transport.close()
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
