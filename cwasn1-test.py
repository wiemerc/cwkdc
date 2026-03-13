import subprocess

from impacket.krb5.constants import PrincipalNameType
from pyasn1.codec.der import encoder

from krb5 import KrbError, PrincipalName


KRB_VERSION = 5
KRB_REALM = "CWTEST.LOCAL"
KRB_SNAME = "krbtgt"


def main():
    err = KrbError(
        pvno=KRB_VERSION,
        sname=PrincipalName(name_type=PrincipalNameType.NT_SRV_INST.value, name_string=(KRB_SNAME, KRB_REALM)),
    )
    print(err.pyasn1_obj)
    subprocess.run(["xxd"], input=encoder.encode(err.pyasn1_obj))


main()
