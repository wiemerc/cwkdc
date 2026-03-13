from dataclasses import field
from datetime import UTC, datetime

from impacket.krb5.asn1 import Int32, KerberosString, KerberosTime, Microseconds, Realm
from impacket.krb5.constants import ApplicationTagNumbers, ErrorCodes, KerberosMessageTypes, PrincipalNameType
from pyasn1.codec.der import encoder
from pyasn1.type.char import GeneralString
from pyasn1.type.constraint import SingleValueConstraint
from pyasn1.type.univ import Integer, OctetString

from asn1 import Asn1Sequence, Asn1SequenceOf


KRB_VERSION = 5


# We don't need the @dataclass decorator because the __init_subclass__() method of Asn1Sequence turns all subclasses into
# dataclasses. See https://stackoverflow.com/a/73347629 for an explanation why we do this.
# As always with dataclasses, fields with default values have to come after fields without. As non-optional components are
# interleaved with  optional ones in the Kerberos types, we have to explicitly specify the tag numbers and can't rely on the field order.

# see https://datatracker.ietf.org/doc/html/rfc4120#appendix-A
class PrincipalName(Asn1Sequence):
    name_type: Integer = field(metadata={"tag": 0})
    name_string: Asn1SequenceOf[GeneralString] = field(metadata={"tag": 1})


# see https://datatracker.ietf.org/doc/html/rfc4120#section-5.9.1
class KrbError(Asn1Sequence):
    stime: KerberosTime = field(metadata={"tag": 4})
    susec: Microseconds = field(metadata={"tag": 5})
    error_code: Int32 = field(metadata={"tag": 6})
    realm: Realm  = field(metadata={"tag": 9})
    sname: PrincipalName = field(metadata={"tag": 10})
    # TODO: Is there a better way to specify the application tag number?
    appl_tag_num: Integer = ApplicationTagNumbers.KRB_ERROR.value
    pvno: Integer = field(default=KRB_VERSION, metadata={"tag": 0, "constraint": SingleValueConstraint(KRB_VERSION)})
    msg_type: Integer = field(default=KerberosMessageTypes.KRB_ERROR.value, metadata={"tag": 1, "constraint": SingleValueConstraint(KerberosMessageTypes.KRB_ERROR.value)})
    ctime: KerberosTime | None = field(default=None, metadata={"tag": 2})
    cusec: Microseconds | None = field(default=None, metadata={"tag": 3})
    crealm: Realm | None = field(default=None, metadata={"tag": 7})
    cname: PrincipalName | None = field(default=None, metadata={"tag": 8})
    e_text: KerberosString | None = field(default=None, metadata={"tag": 11})
    e_data: OctetString | None = field(default=None, metadata={"tag": 12})

    @staticmethod
    def from_params(realm: str, svc_principal: str, code: ErrorCodes, text: str) -> "KrbError":
        now = datetime.now(UTC)
        return KrbError(
            stime=now.strftime("%Y%m%d%H%M%SZ"),
            susec=now.microsecond,
            error_code=code.value,
            realm=realm,
            sname=PrincipalName(name_type=PrincipalNameType.NT_SRV_INST.value, name_string=(svc_principal, realm)),
            e_text=text,
        )
    
    def to_bytes(self) -> bytes:
        return encoder.encode(self.pyasn1_obj)
