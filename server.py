#!/usr/bin/env python3


import asyncio
import sys

from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser
from datetime import datetime, timedelta, timezone

from impacket.krb5.asn1 import (
    AS_REP,
    AS_REQ,
    EncASRepPart,
    EncTicketPart,
    KRB_ERROR,
    LastReq,
    PrincipalName,
    Ticket,
    seq_set,
    seq_set_iter,
)
from impacket.krb5.constants import ApplicationTagNumbers, ErrorCodes, PrincipalNameType, TicketFlags
from impacket.krb5.crypto import Key, _get_enctype_profile, encrypt, get_random_bytes
from impacket.krb5.types import KerberosTime, Principal
from loguru import logger
from pyasn1.codec.der import decoder, encoder


EXIT_OK = 0
EXIT_ERROR = 1

KRB_VERSION = 5
KRB_REALM = "CWTEST.LOCAL"
KRB_SNAME = "krbtgt"
KRB_KNOWN_PRINCIPALS = {
    "consti@CWTEST.LOCAL": "consti123",
    "krbtgt@CWTEST.LOCAL": "krbtgt123",
}
KRB_DEFAULT_TICKET_VALIDITY_TIME_HOURS = 10


class KrbError:
    def __init__(self, code: ErrorCodes, text: str):
        self.code = code
        self.text = text

    def to_asn1(self) -> bytes:
        msg = KRB_ERROR()
        msg["pvno"] = KRB_VERSION
        msg["msg-type"] = ApplicationTagNumbers.KRB_ERROR.value
        now = datetime.now(timezone.utc)
        msg["stime"] = KerberosTime.to_asn1(now)
        msg["susec"] = now.microsecond
        msg["realm"] = KRB_REALM
        msg["error-code"] = self.code.value
        msg["e-text"] = self.text
        sname = seq_set(msg, "sname")
        sname["name-type"] = PrincipalNameType.NT_SRV_INST.value
        sname["name-string"][0] = KRB_SNAME
        sname["name-string"][1] = KRB_REALM
        return encoder.encode(msg)



# Relevant links:
# - https://www.youtube.com/watch?v=pzrtfRpPVM4
# - https://academy.hackthebox.com/module/74/section/701
# - https://datatracker.ietf.org/doc/html/rfc4120
# - https://kerberos.org/software/tutorial.html
class KdcServer:
    def connection_made(self, transport):
        self.transport = transport


    def connection_lost(self, exc):
        pass


    def datagram_received(self, data, addr):
        logger.debug(f"Message received from {addr}, {len(data)} bytes long")
        as_req, _ = decoder.decode(data, asn1Spec=AS_REQ())
        as_req_body = as_req["req-body"]
        cname = as_req_body["cname"]
        realm = str(as_req_body["realm"])
        cpn = str(cname["name-string"][0]) + "@" + realm
        sname = as_req_body["sname"]
        spn = str(sname["name-string"][0]) + "@" + str(sname["name-string"][1])
        enctype_to_use = as_req_body["etype"][0]
        nonce = int(as_req_body["nonce"])
        logger.info(f"Message is AS_REQ: UPN={cpn}, SPN={spn}, nonce={nonce}")

        if cpn in KRB_KNOWN_PRINCIPALS:
            logger.info(f"Client principal '{cpn}' is known")
            client_key = self._create_principal_key(
                enctype=enctype_to_use,
                realm=realm,
                principal_name=cname,
                principal_passwd=KRB_KNOWN_PRINCIPALS[cpn],
            )
            logger.debug(
                f"Created key '{client_key.contents.hex(sep=' ')}' for principal '{cpn}' with encryption type {enctype_to_use} "
                f"(the first one offered by the client)"
            )
        else:
            logger.error(f"Client principal '{cpn}' is not known")
            resp = KrbError(ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN, f"User '{cpn}' is not known")
            self.transport.sendto(resp.to_asn1(), addr)
            return

        if spn in KRB_KNOWN_PRINCIPALS:
            logger.info(f"Service principal '{spn}' is known")
            service_key = self._create_principal_key(
                enctype=enctype_to_use,
                realm=str(sname["name-string"][1]),
                principal_name=sname,
                principal_passwd=KRB_KNOWN_PRINCIPALS[spn],
            )
            logger.debug(
                f"Created key '{service_key.contents.hex(sep=' ')}' for principal '{spn}' with encryption type {enctype_to_use} "
                f"(the first one offered by the client)"
            )
        else:
            logger.error(f"Service principal '{spn}' is not known")
            resp = KrbError(ErrorCodes.KDC_ERR_S_PRINCIPAL_UNKNOWN, f"User '{spn}' is not known")
            self.transport.sendto(resp.to_asn1(), addr)
            return
        
        session_key = self._create_session_key(enctype_to_use)
        logger.debug(
            f"Created session key '{session_key.contents.hex(sep=' ')}' for encryption type {enctype_to_use} "
            f"(the first one offered by the client)"
        )
        as_rep = self._create_as_rep(cname, realm, session_key, service_key, client_key, nonce)
        logger.debug(f"Created message {as_rep}")
        logger.debug("Sending AS_REP message to client")
        self.transport.sendto(encoder.encode(as_rep), addr)


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


    def _create_tgt(
        self,
        ticket: Ticket,
        client_principal_name: PrincipalName,
        client_realm: str,
        session_key: Key,
        service_key: Key,
        flags: list[TicketFlags] = [],
        duration: timedelta = timedelta(hours=KRB_DEFAULT_TICKET_VALIDITY_TIME_HOURS),
    ) -> Ticket:
        """
        Create a ticket-granting ticket (TGT)
        """
        enc_ticket_part = EncTicketPart()

        flags_value = sum(1 << flag.value for flag in flags)
        enc_ticket_part["flags"] = bin(flags_value)[2:].zfill(32)

        key = seq_set(enc_ticket_part, "key")
        key["keytype"] = session_key.enctype
        key["keyvalue"] = session_key.contents

        enc_ticket_part["crealm"] = client_realm
        cname = seq_set(enc_ticket_part, "cname")
        cname["name-type"] = client_principal_name["name-type"]
        cname["name-string"][0] = str(client_principal_name["name-string"][0])
        cname["name-string"][1] = client_realm

        # Set transited encoding, empty for direct authentication
        transited = seq_set(enc_ticket_part, "transited")
        transited["tr-type"] = 0
        transited["contents"] = b""

        now = datetime.now(timezone.utc)
        enc_ticket_part["authtime"] = KerberosTime.to_asn1(now)
        enc_ticket_part["starttime"] = KerberosTime.to_asn1(now)
        enc_ticket_part["endtime"] = KerberosTime.to_asn1(now + duration)

        encoded_enc_ticket_part = encoder.encode(enc_ticket_part)
        # Key usage 2 = ticket to be used in AS-REP / TGS-REP messages (encrypted with the service key)
        cipher_text = encrypt(
            key=service_key,
            keyusage=2,
            plaintext=encoded_enc_ticket_part,
            confounder=b""
        )

        ticket["tkt-vno"] = KRB_VERSION
        ticket["realm"] = KRB_REALM
        sname = seq_set(ticket, "sname")
        sname["name-type"] = PrincipalNameType.NT_SRV_INST.value
        sname["name-string"][0] = KRB_SNAME
        sname["name-string"][1] = KRB_REALM
        enc_part = seq_set(ticket, "enc-part")
        enc_part["etype"] = service_key.enctype
        enc_part["cipher"] = cipher_text

        logger.debug(f"Created TGT {ticket}")


    def _create_as_rep(
        self,
        client_principal_name: PrincipalName,
        client_realm: str,
        session_key: Key,
        service_key: Key,
        client_key: Key,
        nonce: int,
        flags: list[TicketFlags] = [],
        duration: timedelta = timedelta(hours=KRB_DEFAULT_TICKET_VALIDITY_TIME_HOURS),
    ) -> AS_REP:
        """
        Create an AS-REP (Authentication Service Reply) message.
        """
        now = datetime.now(timezone.utc)
        enc_as_rep_part = EncASRepPart()

        key = seq_set(enc_as_rep_part, "key")
        key["keytype"] = session_key.enctype
        key["keyvalue"] = session_key.contents

        last_requests = LastReq().setComponentByPosition(0)
        last_requests[0]["lr-type"] = 0  # means no last request info available
        last_requests[0]["lr-value"] = KerberosTime.to_asn1(now)
        seq_set_iter(enc_as_rep_part, "last-req", last_requests)

        enc_as_rep_part["nonce"] = nonce

        flags_value = sum(1 << flag.value for flag in flags)
        enc_as_rep_part["flags"] = bin(flags_value)[2:].zfill(32)

        enc_as_rep_part["authtime"] = KerberosTime.to_asn1(now)
        enc_as_rep_part["starttime"] = KerberosTime.to_asn1(now)
        enc_as_rep_part["endtime"] = KerberosTime.to_asn1(now + duration)

        enc_as_rep_part["srealm"] = KRB_REALM
        sname = seq_set(enc_as_rep_part, "sname")
        sname["name-type"] = PrincipalNameType.NT_SRV_INST.value
        sname["name-string"][0] = KRB_SNAME
        sname["name-string"][1] = KRB_REALM

        # Key usage 3 = AS-REP encrypted part (encrypted with client key)
        cipher_text = encrypt(
            key=client_key,
            keyusage=3,
            plaintext=encoder.encode(enc_as_rep_part),
            confounder=b""
        )

        as_rep = AS_REP()
        as_rep["pvno"] = KRB_VERSION
        as_rep["msg-type"] = ApplicationTagNumbers.AS_REP.value
        as_rep["crealm"] = client_realm

        ticket = seq_set(as_rep, "ticket")
        self._create_tgt(ticket, client_principal_name, client_realm, session_key, service_key)

        cname = seq_set(as_rep, "cname")
        cname["name-type"] = client_principal_name["name-type"]
        cname["name-string"][0] = str(client_principal_name["name-string"][0])
        cname["name-string"][1] = client_realm

        enc_part = seq_set(as_rep, "enc-part")
        enc_part["etype"] = client_key.enctype
        enc_part["cipher"] = cipher_text

        return as_rep


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
        KdcServer,
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
