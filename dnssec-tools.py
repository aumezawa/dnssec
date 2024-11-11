#!/bin/python

from __future__ import print_function
import base64
import datetime
import ecdsa ## must be installed by "python -m pip install ecdsa"
import hashlib
import re
import struct
import sys

__version__ = "0.0.1-beta"
__author__  = "aumezawa"


################################################################################

def error_handling():
    """
    """
    exception_type, exception_object, exception_traceback = sys.exc_info()
    func_name = exception_traceback.tb_frame.f_code.co_name
    line_no = exception_traceback.tb_lineno
    print(f"Exception at <{ func_name }, line { line_no }>: { exception_object }")
    sys.exit(-1)

################################################################################

def date_to_iso_format(date):
    """
    Converting "YYYYMMDDhhmmss" to "YYYY-MM-DDThh:mm:ss+00:00Z" for datetime

    Parameters
    ----------
    date: str

    Returns
    -------
    iso_format: str
    """
    iso_format = f"{ date[0:4] }-{ date[4:6] }-{ date[6:8] }Z{ date[8:10] }:{ date[10:12] }:{ date[12:14] }+00:00"
    return iso_format

################################################################################

### ref: [RFC 1035 Section 3.2.2](https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2)
### ref: [RFC 4034 Section 7](https://datatracker.ietf.org/doc/html/rfc4034#section-7)
def convert_record_type(type_str):
    """
    Parameters
    ----------
    type_str: str

    Returns
    -------
    type_int: int
    """
    if type_str == "A":
        type_int = 1
    elif type_str == "DS":
        type_int = 43
    elif type_str == "RRSIG":
        type_int = 46
    elif type_str == "DNSKEY":
        type_int = 48
    else:
        print(f"Unsupported record type: { type_str }")
        sys.exit(-1)
    #
    return type_int


### ref: [RFC 1035 Section 3.2.4](https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.4)
def convert_class_code(class_str):
    """
    Parameters
    ----------
    class_str: str

    Returns
    -------
    class_int: int
    """
    if class_str == "IN":
        class_int = 1
    else:
        print(f"Unsupported record type: { class_str }")
        sys.exit(-1)
    #
    return class_int


### ref: [RFC 4034 Section 4.3](https://datatracker.ietf.org/doc/html/rfc4034#section-4.3)
def encode_name(name_str):
    """
    Parameters
    ----------
    name_str: str

    Returns
    -------
    encoded_name: bytes
    """
    if name_str.endswith(".") is False:
        name_str += "."
    encoded_name = bytes()
    for chunk in name_str.split("."):
        encoded_name += struct.pack("B", len(chunk)) + chunk.encode()
    #
    return encoded_name


### ref: [RFC 1035 Section 3.2.1](https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.1)
def input_record(input_type):
    """
    Parameters
    ----------
    input_type: str

    Returns
    -------
    owner_name: str
    ttl: int
    class_code: int
    record_type: int
    data: any[]
    """
    RECORD_FIELDS = 5
    #
    fleids = re.sub(r"\s+", " ", input(f"please input { input_type } record: ")).split(" ")
    if len(fleids) < RECORD_FIELDS:
        print("Invalid. Record format is: <owner_name> <ttl> <class_code> <record_type> <data...>")
        sys.exit(-1)
    #
    try:
        owner_name = fleids[0]
        ttl = int(fleids[1])
        class_code = convert_class_code(fleids[2])
        record_type = convert_record_type(fleids[3])
        rdata = fleids[4:]
    except:
        error_handling()
    #
    if record_type != convert_record_type(input_type):
        print("Invalid. Record type did not match.")
        sys.exit(-1)
    #
    return (owner_name, ttl, class_code, record_type, rdata)


### ref: [RFC 1035 Section 3.4.1](https://datatracker.ietf.org/doc/html/rfc1035#section-3.4.1)
def input_a_record():
    """
    Returns
    -------
    owner_name: str
    ttl: int
    class_code: int
    record_type: int
    ip_address: str
    """
    A_RDATA_FIELDS = 1
    #
    (owner_name, ttl, class_code, record_type, rdata) = input_record("A")
    if len(rdata) < A_RDATA_FIELDS:
        print("Invalid. A record format is: <owner_name> <ttl> <class_code> <record_type> <ip_address>")
        sys.exit(-1)
    #
    try:
        ip_address = rdata[0]
    except:
        error_handling()
    #
    return (owner_name, ttl, class_code, record_type, ip_address)


### ref: [RFC 4034 Section 5.1](https://datatracker.ietf.org/doc/html/rfc4034#section-5.1)
def input_ds_record():
    """
    Returns
    -------
    owner_name: str
    ttl: int
    class_code: int
    record_type: int
    keytag: int
    algorithm: int
    digest_type: int
    digest: bytes
    """
    DS_RDDTA_FIELDS = 4
    #
    (owner_name, ttl, class_code, record_type, rdata) = input_record("DS")
    if len(rdata) < DS_RDDTA_FIELDS:
        print("Invalid. DS record format is: <owner_name> <ttl> <class_code> <record_type> <keytag> <algorithm> <digest_type> <digest>")
        sys.exit(-1)
    #
    try:
        keytag = int(rdata[0])
        algorithm = int(rdata[1])
        digest_type = int(rdata[2])
        digest = bytes.fromhex("".join(rdata[3:]))
    except:
        error_handling()
    #
    return (owner_name, ttl, class_code, record_type, keytag, algorithm, digest_type, digest)


### ref: [RFC 4034 Section 3.1](https://datatracker.ietf.org/doc/html/rfc4034#section-3.1)
def input_rrsig_record():
    """
    Returns
    -------
    owner_name: str
    ttl: int
    class_code: int
    record_type: int
    target_record_type: int
    algorithm: int
    labels: int
    original_ttl: int
    expiration: int
    inception: int
    keytag: int
    signer_name: str
    signature: bytes
    """
    RRSIG_RDDTA_FIELDS = 9
    #
    (owner_name, ttl, class_code, record_type, rdata) = input_record("RRSIG")
    if len(rdata) < RRSIG_RDDTA_FIELDS:
        print("Invalid. RRSIG record format is: <owner_name> <ttl> <class_code> <record_type> <target_record_type> <algorithm> <labels> <original_ttl> <expiration> <inception> <keytag> <signer> <data...>")
        sys.exit(-1)
    #
    try:
        target_record_type = convert_record_type(rdata[0])
        algorithm = int(rdata[1])
        labels = int(rdata[2])
        original_ttl = int(rdata[3])
        expiration = int(datetime.datetime.fromisoformat(date_to_iso_format(rdata[4])).timestamp())
        inception = int(datetime.datetime.fromisoformat(date_to_iso_format(rdata[5])).timestamp())
        keytag = int(rdata[6])
        signer_name = rdata[7]
        signature = base64.b64decode("".join(rdata[8:]))
    except:
        error_handling()
    #
    return (owner_name, ttl, class_code, record_type, target_record_type, algorithm, labels, original_ttl, expiration, inception, keytag, signer_name, signature)


### ref: [RFC 4045 Section 2.1](https://datatracker.ietf.org/doc/html/rfc4034#section-2.1)
def input_dnskey_record():
    """
    Returns
    -------
    owner_name: str
    ttl: int
    class_code: int
    record_type: int
    flag: int
    protocol: int
    algorithm: int
    public_key: bytes
    """
    DNSKEY_RDATA_FIELDS = 4
    #
    (owner_name, ttl, class_code, record_type, rdata) = input_record("DNSKEY")
    if len(rdata) < DNSKEY_RDATA_FIELDS:
        print("Invalid. DNSKEY record format is: <owner_name> <ttl> <class_code> <record_type> <flag> <protocol> <algorithm> <public_key>")
        sys.exit(-1)
    #
    try:
        flag = int(rdata[0])
        protocol = int(rdata[1])
        algorithm = int(rdata[2])
        public_key = base64.b64decode("".join(rdata[3:]))
    except:
        error_handling()
    #
    return (owner_name, ttl, class_code, record_type, flag, protocol, algorithm, public_key)


### ref: [RFC 1035 Section 3.4.1](https://datatracker.ietf.org/doc/html/rfc1035#section-3.4.1)
def encode_a_rdata(ip_address):
    """
    Parameters
    ----------
    ip_address: str

    Returns
    -------
    a_rdate: byte
    """
    a_rdata = bytes()
    for octet in ip_address.split("."):
        a_rdata += struct.pack("B", int(octet))
    return a_rdata


### ref: [RFC 4034 Section 5.1](https://datatracker.ietf.org/doc/html/rfc4034#section-5.1)
def encode_ds_rdata(keytag, algorithm, digest_type, digest):
    """
    Parameters
    ----------
    keytag: int
    algorithm: int
    digest_type: int
    digest: bytes

    Returns
    -------
    ds_rdate: byte
    """
    ds_rdate = bytes()
    ds_rdate += struct.pack("!H", keytag)
    ds_rdate += struct.pack("B", algorithm)
    ds_rdate += struct.pack("B", digest_type)
    ds_rdate += digest
    return ds_rdate


### ref: [RFC 4034 Section 3.1.8.1](https://datatracker.ietf.org/doc/html/rfc4034#section-3.1.8.1)
def encode_rrsig_rdata(target_record_type, algorithm, labels, original_ttl, expiration, inception, keytag, signer_name):
    """
    Parameters
    ----------
    target_record_type: int
    algorithm: int
    labels: int
    original_ttl: int
    expiration: int
    inception: int
    keytag: int
    signer_name: str

    Returns
    -------
    rrsig_rdata: bytes
    """
    rrsig_rdata = bytes()
    rrsig_rdata += struct.pack("!H", target_record_type)
    rrsig_rdata += struct.pack("B", algorithm)
    rrsig_rdata += struct.pack("B", labels)
    rrsig_rdata += struct.pack("!I", original_ttl)
    rrsig_rdata += struct.pack("!I", expiration)
    rrsig_rdata += struct.pack("!I", inception)
    rrsig_rdata += struct.pack("!H", keytag)
    rrsig_rdata += encode_name(signer_name)
    return rrsig_rdata


### ref: [RFC 4034 Section 5](https://datatracker.ietf.org/doc/html/rfc4034#section-5)
def encode_dnskey_rdata(flag, protocol, algorithm, public_key):
    """
    Parameters
    ----------
    flag: int
    protocol: int
    algorithm: int
    public_key: bytes

    Returns
    -------
    dnskey_rdate: byte
    """
    dnskey_rdate = bytes()
    dnskey_rdate += struct.pack("!H", flag)
    dnskey_rdate += struct.pack("B", protocol)
    dnskey_rdate += struct.pack("B", algorithm)
    dnskey_rdate += public_key
    return dnskey_rdate


### ref: [RFC 4034 Section 3.1.8.1](https://datatracker.ietf.org/doc/html/rfc4034#section-3.1.8.1)
def encode_rr(owner_name, record_type, class_code, original_ttl, rdata):
    """
    Parameters
    ----------
    owner_name: str
    record_type: int
    class_code: int
    original_ttl: int
    rdata: bytes

    Returns
    -------
    rr: bytes
    """
    rr = bytes()
    rr += encode_name(owner_name)
    rr += struct.pack("!H", record_type)
    rr += struct.pack("!H", class_code)
    rr += struct.pack("!I", original_ttl)
    rr += struct.pack("!H", len(rdata))
    rr += rdata
    return rr


### ref: [RFC 4045 Appendix B](https://datatracker.ietf.org/doc/html/rfc4034#appendix-B)
def extract_keytag_from_dnskey(dnskey_rdate):
    """
    Parameters
    ----------
    dnskey_rdate: bytes

    Returns
    -------
    keytag: int
    """
    key = dnskey_rdate
    keysize = len(key)
    ac = 0
    for i in range(keysize):
        if i % 2 == 1:
            ac += key[i]
        else:
            ac += key[i] << 8
    ac += (ac >> 16) & 0xFFFF
    keytag = ac & 0xFFFF
    return keytag

################################################################################

### ref: [RFC 4034 Section 5.1.4](https://datatracker.ietf.org/doc/html/rfc4034#section-5.1.4)
def validate_ds_digest(owner_name, digest_type, digest, dnskey_rdata):
    """
    Parameters
    ----------
    owner_name: string
    digest_type: int
    digest: bytes
    dnskey_rdata: bytes

    Returns
    -------
    result: boolean
    """
    ### ref: [RFC 4509 Section 5](https://datatracker.ietf.org/doc/html/rfc4509#section-5)
    DIGEST_SHA256 = 2
    #
    result = False
    if (digest_type == DIGEST_SHA256):
        ### ref: [RFC 4509 Section 2.1](https://datatracker.ietf.org/doc/html/rfc4509#section-2.1)
        if bytes.fromhex(hashlib.sha256(encode_name(owner_name) + dnskey_rdata).hexdigest()) == digest:
            result = True
    else:
        print(f"Unsupported digest type: { digest }")
        sys.exit(-1)
    #
    return result


def validate_rrsig_signature(algorithm, rdata_rr, signature, dnskey_public_key):
    """
    Parameters
    ----------
    algorithm: int
    hash: byte
    signature: bytes
    dnskey_public_key: bytes

    Returns
    -------
    result: boolean
    """
    ### ref: [RFC 8624 Section 3.1](https://datatracker.ietf.org/doc/html/rfc8624#section-3.1)
    ALGORITHM_RSASHA256 = 8
    ALGORITHM_ECDSAP256SHA256 = 13
    #
    result = False
    if algorithm == ALGORITHM_RSASHA256:
        ### ref: [RFC 3110 Section 2](https://datatracker.ietf.org/doc/html/rfc3110#section-2)
        index = 0
        #
        exponent_length = dnskey_public_key[0]
        index += 1
        if exponent_length == 0:
            exponent_length = dnskey_public_key[1] << 8 + dnskey_public_key[2]
            index += 2
        #
        exponent = int.from_bytes(dnskey_public_key[index:(index + exponent_length)], byteorder="big")
        index += exponent_length
        #
        modulus = int.from_bytes(dnskey_public_key[index:], byteorder="big")
        #
        encoded = int.from_bytes(signature, byteorder="big")
        #
        ### ref: [RFC 5702 Section 3](https://datatracker.ietf.org/doc/html/rfc5702#section-3)
        decoded_int = pow(encoded, exponent, modulus)
        decoded = decoded_int.to_bytes((decoded_int.bit_length() + 7) // 8, byteorder="big")
        #
        index = 0
        #
        decoded[index] ## header: must be 0x01
        index += 1
        #
        while(decoded[index] == 0xff): ## padding: must be 0xFF*
            index += 1
        #
        decoded[index] ## header: must be 0x00
        index += 1
        #
        decoded[index:(index + 19)] ## prefix: SHA-256 or SHA-512
        index += 19
        #
        decoded_hash = decoded[index:]
        #
        original_hash = bytes.fromhex(hashlib.sha256(rdata_rr).hexdigest())
        #
        if decoded_hash == original_hash:
            result = True
    elif algorithm == ALGORITHM_ECDSAP256SHA256:
        verifying_key = ecdsa.VerifyingKey.from_string(dnskey_public_key, curve=ecdsa.NIST256p, hashfunc=hashlib.sha256)
        if verifying_key.verify(signature, rdata_rr, hashlib.sha256):
            result = True
    else:
        print(f"Unsupported algorithm type: { algorithm }")
        sys.exit(-1)
    #
    return result

################################################################################

def validate_ds_digest_main():
    """
    Returns
    -------
    result: boolean
    """
    (_, _, _, _, keytag, _, digest_type, digest) = input_ds_record()
    (owner_name, _, _, _, flag, protocol, algorithm, public_key) = input_dnskey_record()
    #
    dnskey_rdata = encode_dnskey_rdata(flag, protocol, algorithm, public_key)
    #
    if extract_keytag_from_dnskey(dnskey_rdata) != keytag:
        print("Invalid. Keytags do not match.")
        sys.exit(-1)
    #
    result = validate_ds_digest(owner_name, digest_type, digest, dnskey_rdata)
    result_str = "Valid" if result else "Invalid"
    print()
    print(f"The digest of DS record is: { result_str }")
    return result


def validate_a_record_signature_main():
    # TODO: should support multi records
    """
    Returns
    -------
    result: boolean
    """
    (_, _, _, _, target_record_type, algorithm, labels, original_ttl, expiration, inception, keytag, signer_name, signature) = input_rrsig_record()
    (owner_name, _, class_code, record_type, ip_address) = input_a_record()
    (_, _, _, _, _, _, _, public_key) = input_dnskey_record()
    #
    ### ref: (RFC 4043 Section 3.1.8.1)[https://datatracker.ietf.org/doc/html/rfc4034#section-3.1.8.1]
    rrsig_rdata = encode_rrsig_rdata(target_record_type, algorithm, labels, original_ttl, expiration, inception, keytag, signer_name)
    #
    a_rdata = encode_a_rdata(ip_address)
    rr = encode_rr(owner_name, record_type, class_code, original_ttl, a_rdata)
    #
    result = validate_rrsig_signature(algorithm, rrsig_rdata + rr, signature, public_key)
    result_str = "Valid" if result else "Invalid"
    print()
    print(f"The signature of A record is: { result_str }")
    return result


def validate_ds_record_signature_main():
    # TODO: must do unit test
    """
    Returns
    -------
    result: boolean
    """
    (_, _, _, _, target_record_type, algorithm, labels, original_ttl, expiration, inception, keytag, signer_name, signature) = input_rrsig_record()
    (owner_name, _, class_code, record_type, keytag, ds_algorithm, digest_type, digest) = input_ds_record()
    (_, _, _, _, _, _, _, public_key) = input_dnskey_record()
    #
    ### ref: (RFC 4043 Section 3.1.8.1)[https://datatracker.ietf.org/doc/html/rfc4034#section-3.1.8.1]
    rrsig_rdata = encode_rrsig_rdata(target_record_type, algorithm, labels, original_ttl, expiration, inception, keytag, signer_name)
    #
    ds_rdata = encode_ds_rdata(keytag, ds_algorithm, digest_type, digest)
    rr = encode_rr(owner_name, record_type, class_code, original_ttl, ds_rdata)
    #
    result = validate_rrsig_signature(algorithm, rrsig_rdata + rr, signature, public_key)
    result_str = "Valid" if result else "Invalid"
    print()
    print(f"The signature of DS record is: { result_str }")
    return


def validate_dnskey_record_signature_main():
    """
    Returns
    -------
    result: boolean
    """
    (_, _, _, _, target_record_type, algorithm, labels, original_ttl, expiration, inception, keytag, signer_name, signature) = input_rrsig_record()
    (zsk_owner_name, _, zsk_class_code, zsk_record_type, zsk_flag, zsk_protocol, zsk_algorithm, zsk_public_key) = input_dnskey_record()
    (ksk_owner_name, _, ksk_class_code, ksk_record_type, ksk_flag, ksk_protocol, ksk_algorithm, ksk_public_key) = input_dnskey_record()
    #
    ### ref: (RFC 4043 Section 3.1.8.1)[https://datatracker.ietf.org/doc/html/rfc4034#section-3.1.8.1]
    rrsig_rdata = encode_rrsig_rdata(target_record_type, algorithm, labels, original_ttl, expiration, inception, keytag, signer_name)
    #
    zsk_dnskey_rdata = encode_dnskey_rdata(zsk_flag, zsk_protocol, zsk_algorithm, zsk_public_key)
    zsk_rr = encode_rr(zsk_owner_name, zsk_record_type, zsk_class_code, original_ttl, zsk_dnskey_rdata)
    #
    ksk_dnskey_rdata = encode_dnskey_rdata(ksk_flag, ksk_protocol, ksk_algorithm, ksk_public_key)
    ksk_rr = encode_rr(ksk_owner_name, ksk_record_type, ksk_class_code, original_ttl, ksk_dnskey_rdata)
    #
    result = validate_rrsig_signature(algorithm, rrsig_rdata + zsk_rr + ksk_rr, signature, ksk_public_key)
    result_str = "Valid" if result else "Invalid"
    print()
    print(f"The signature of DNSKEY record is: { result_str }")
    return result


def extract_keytag_from_dnskey_main():
    """
    Returns
    -------
    keytag: int
    """
    (_, _, _, _, flag, protocol, algorithm, public_key) = input_dnskey_record()
    #
    dnskey_rdata = encode_dnskey_rdata(flag, protocol, algorithm, public_key)
    keytag = extract_keytag_from_dnskey(dnskey_rdata)
    #
    print()
    print(f"The Key Tag is: { keytag }")
    return keytag


MENU = """
Menu:
1) Verify digest of DS record with KSK
2) Verify signature of single A record with ZSK
3) Verify signature of DS record with ZSK (not validated)
4) Verify signature of DNSKEY record with KSK
...
9) Extract Key Tag from ZSK/KSK
"""
def main():
    print(MENU)
    try:
        select = int(input("Choose one of them: "))
        print()
    except:
        error_handling()
    #
    if select == 1:
        validate_ds_digest_main()
    elif select == 2:
        validate_a_record_signature_main()
    elif select == 3:
        validate_ds_record_signature_main()
    elif select == 4:
        validate_dnskey_record_signature_main()
    elif select == 9:
        extract_keytag_from_dnskey_main()
    else:
        print("Invalid. You chose an unsupport menu.")
    return


if __name__ == "__main__":
    main()
    sys.exit(0)


""" TEST RECORD DATA
example.com. 86400 IN DS 370 13 2 BE74359954660069D5C63D200C39F5603827D7DD02B56F120EE9F3A86764247C

example.com. 3600 IN DNSKEY 256 3 13 OtuN/SL9sE+SDQ0tOLeezr1KzUNi77FflTjxQylUhm3V 7m13Vz9tYQucSGK0pyxISo9CQsszubAwJSypq3li3g==
example.com. 3600 IN DNSKEY 257 3 13 kXKkvWU3vGYfTJGl3qBd4qhiWp5aRs7YtkCJxD2d+t7K Xqwahww5IgJtxJT2yFItlggazyfXqJEVOmMJ3qT0tQ==

example.com. 3600 IN A 93.184.215.14
example.com. 3600 IN RRSIG A 13 2 3600 20241117173922 20241027165426 42464 example.com. i547XFAHRMLksexkC9j18YvDcsDSE1SNVorFihK5mYWJ /wG4zqh3ELOJ/HiVXQ0hdmgFvMj16XbPQJkqIJjI1Q==

---

eng-blog.iij.ad.jp. 419 IN A 203.180.155.24
eng-blog.iij.ad.jp. 1347  IN RRSIG A 8 4 86400 20201217151006 20201117151006 5628 iij.ad.jp. ITYLFLnc7s3rB0aZNVSrCsUNBs3vRztF87XjgFHf6Q8yQ2GPFX72s/w5 m5dUDeV/UJBEwB7udTAPxeNarqaoe/Ot0ExkjVpZ2u5zQXdO//ExbmBs 8YX/xCBTJJX6te0odwpJBzFmL2Ecxs6VNm71/xugV2EKIzzeI/vKLJkY Qhg=

iij.ad.jp. 1488 IN  DNSKEY  256 3 8 AwEAAbdSiZ0RxmtsZUbE1v5kJWi3tXYBQYmZZmYVyw5QgSI7zSoOIcdW 2NoSX+rarklHdnBZKHgBE/lylRxxEi5pGQaJFLVEMBbUo5leb9nmikWG +GxWJL6dZic5LIt3hyAZ0r9jNJN/apzbQh16X41X8gE4lMymlMDXRf6W SbfKReW9
iij.ad.jp. 1488 IN  DNSKEY  257 3 8 AwEAAfByl5y3fBxdJ+ALSWRc55A8Dp8ZBr+7JxJcml1Ys/bmvVRvG72e s+DvOBR1jjS1l1j74e2eP89ClInWPVajZKc4AX69/btKQznfwC35secx Jniud6VctkF35xqfVZZnXOetF4+QtJtSYhVNg/hirc7HuSpgnzggqt75 X2qaA6THYR9oVBuV+Bu/CrN+KV3qs//r0Fcr7b6Q2VMRWWZe+uqFy5ij PUQq+nXGHgpYxY1CgWH4wRK8WWzUXzE55otuajaBhTH3pi7tz9nKqi7J gBs/l051Ezg7rFfrj857kprMWUu5oacLs3WfZOA0T6fx8aO792HkgEEr Th0LvVWVMqU=
iij.ad.jp. 2176 IN RRSIG DNSKEY 8 3 86400 20201217151006 20201117151006 48472 iij.ad.jp. IvflOJImlu9iSR7LO80wv9o4FJsmy0UDB1gmIPzbqaTIa+z9ePG+tSYa z6HEck75SWWeZeXM0zbAuYX5/had7qTh+IFhO1m9GcIg9+KTdHrKR9jP 9DuVvk3IGJXTpO/L5fPfwsFPrSqfktO9ug6mnwrXshqKIk16NcTggpdd k22Wt1ksDDgZ/61p9j5Zk0CTR2t8/I/rwCcWc7zUsyLAF2rbcBufpsn/ PEz/qPnCgFRjSRkeDln0MaX9NH+48A5vYbthLhtGgc2pviIACc6EYaw2 HSggSD2zR1mJLy7P4APvgu1ijSKXpgF4SpRmhqeuYLkGMbvKnK87N5LK vL7VKg==
"""

""" TEST RRSIG A RAW DATA
00000000  00 01 08 04 00 01 51 80  5f db 74 ce 5f b3 e7 ce  |......Q._.t._...|
00000010  15 fc 03 69 69 6a 02 61  64 02 6a 70 00 08 65 6e  |...iij.ad.jp..en|
00000020  67 2d 62 6c 6f 67 03 69  69 6a 02 61 64 02 6a 70  |g-blog.iij.ad.jp|
00000030  00 00 01 00 01 00 01 51  80 00 04 cb b4 9b 18     |.......Q.......|
"""