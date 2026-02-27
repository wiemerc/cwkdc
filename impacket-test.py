from datetime import datetime, timezone

from impacket.krb5.asn1 import EncASRepPart, LastReq, seq_set_iter
from impacket.krb5.types import KerberosTime

now = datetime.now(timezone.utc)
enc_as_rep_part = EncASRepPart()

last_requests = LastReq().setComponentByPosition(0)
last_requests[0]["lr-type"] = 0  # means no last request info available
last_requests[0]["lr-value"] = KerberosTime.to_asn1(now)
seq_set_iter(enc_as_rep_part, "last-req", last_requests)

enc_as_rep_part["nonce"] = 123
