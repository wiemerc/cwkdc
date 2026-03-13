import subprocess

from impacket.krb5.constants import ErrorCodes

from krb5 import KrbError


KRB_VERSION = 5
KRB_REALM = "CWTEST.LOCAL"
KRB_SVC_PRINCIPAL = "krbtgt"


def main():
    err = KrbError.from_params(
        KRB_REALM,
        KRB_SVC_PRINCIPAL,
        ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN,
        f"Client principal 'constix@CWTEST.LOCAL' is not known",
    )
    print(err.pyasn1_obj)
    subprocess.run(["xxd"], input=err.to_bytes())


main()
