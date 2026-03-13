from dataclasses import dataclass, field

from impacket.krb5.constants import ApplicationTagNumbers
from pyasn1.type.char import GeneralString
from pyasn1.type.constraint import ValueRangeConstraint
from pyasn1.type.univ import Integer

from asn1 import Asn1Sequence, Asn1SequenceOf


# see https://datatracker.ietf.org/doc/html/rfc4120#appendix-A
@dataclass
class PrincipalName(Asn1Sequence):
    name_type: Integer
    name_string: Asn1SequenceOf[GeneralString]


# see https://datatracker.ietf.org/doc/html/rfc4120#section-5.9.1
@dataclass
class KrbError(Asn1Sequence):
    # TODO: How to declare constant fields like pvno? It has to come before the other fields because the order determines the
    # tag values.
    # TODO: Is there a better way to specify the application tag number?
    pvno: Integer = field(metadata={"constraint": ValueRangeConstraint(5, 5)})
    sname: PrincipalName
    appl_tag_num: Integer = ApplicationTagNumbers.KRB_ERROR.value
