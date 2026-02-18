#!/usr/bin/env python3


import asyncio
import sys

from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser
from datetime import datetime, timezone

from impacket.krb5.asn1 import AS_REQ, KRB_ERROR, seq_set
from impacket.krb5.constants import ApplicationTagNumbers, ErrorCodes, PrincipalNameType
from loguru import logger
from pyasn1.codec.der import decoder, encoder


EXIT_OK = 0
EXIT_ERROR = 1

KRB_REALM = "CWTEST.LOCAL"
KRB_SNAME = "krbtgt"
KRB_KNOWN_USER_PRINCIPAL_NAMES = [
    "consti@CWTEST.LOCAL",
]


class KrbError:
    def __init__(self, code: ErrorCodes, text: str):
        self.code = code
        self.text = text

    def to_bytes(self) -> bytes:
        msg = KRB_ERROR()
        msg["pvno"] = 5
        msg["msg-type"] = ApplicationTagNumbers.KRB_ERROR.value
        now = datetime.now(timezone.utc)
        msg["stime"] = now.strftime("%Y%m%d%H%M%SZ")
        msg["susec"] = now.microsecond
        msg["realm"] = KRB_REALM
        msg["error-code"] = self.code.value
        msg["e-text"] = self.text

        # TODO: Why doesn't the code below work?
        # sname = PrincipalName()
        # sname["name-type"] = PrincipalNameType.NT_SRV_INST.value
        # sname["name-string"][0] = KRB_SNAME
        # sname["name-string"][1] = KRB_REALM
        # resp["sname"] = sname
        sname_component = seq_set(msg, "sname")
        sname_component["name-type"] = PrincipalNameType.NT_SRV_INST.value
        seq_set(sname_component, "name-string")
        sname_component["name-string"][0] = KRB_SNAME
        sname_component["name-string"][1] = KRB_REALM
        return encoder.encode(msg)



# Relevant links:
# - https://www.youtube.com/watch?v=5N242XcKAsM
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
        upn = str(cname["name-string"][0]) + "@" + realm
        sname = req_body["sname"]
        spn = str(sname["name-string"][0]) + "@" + str(sname["name-string"][1])
        nonce = int(req_body["nonce"])
        logger.debug(f"Message is AS-REQ: UPN={upn}, SPN={spn}, nonce={nonce}")

        if upn in KRB_KNOWN_USER_PRINCIPAL_NAMES:
            logger.info(f"User '{upn}' is known")
            # TODO
        else:
            logger.error(f"User '{upn}' is not known")
            resp = KrbError(ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN, f"User '{upn}' is not known")
            self.transport.sendto(resp.to_bytes(), addr)


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
