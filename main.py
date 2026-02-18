#!/usr/bin/env python3


import asyncio
import sys

from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser
# to supress warnings from scapy:
import logging
logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)
from scapy.layers.kerberos import KRB_AS_REQ, KRB_ERROR
from loguru import logger


EXIT_OK = 0
EXIT_ERROR = 1

KRB_REALM = b"CWTEST.LOCAL"
KRB_KNOWN_USER_PRINCIPAL_NAMES = [
    "consti@CWTEST.LOCAL",
]


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
        req = KRB_AS_REQ(data)
        upn = req.reqBody.cname.nameString[0].val.decode() + "@" + req.reqBody.realm.val.decode()
        spn = req.reqBody.sname.nameString[0].val.decode() + "@" + req.reqBody.sname.nameString[1].val.decode()
        logger.debug(f"Message is AS-REQ: UPN={upn}, SPN={spn}, nonce={req.reqBody.nonce.val}")
        if upn in KRB_KNOWN_USER_PRINCIPAL_NAMES:
            logger.info(f"User '{upn}' is known")
            # TODO
        else:
            logger.error(f"User '{upn}' is not known")
            resp = KRB_ERROR(
                realm=KRB_REALM,
                # TODO: Set the remaining attributes
                errorCode="KDC_ERR_C_PRINCIPAL_UNKNOWN",
                eText=f"User '{upn}' is not known"
            )
            self.transport.sendto(bytes(resp), addr)


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
