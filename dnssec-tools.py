#!/bin/python

from __future__ import print_function
import base64
import datetime
import ecdsa ## must be installed by "python -m pip install ecdsa"
import hashlib
import re
import struct
import sys

__version__ = "0.0.1"
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
    elif type_str == "NS":
        type_int = 2
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
    encoded_name = bytes()
    if name_str == ".":
        encoded_name += struct.pack("B", 0)
    else:
        if name_str.endswith(".") is False:
            name_str += "."
        for chunk in name_str.split("."):
            encoded_name += struct.pack("B", len(chunk)) + chunk.encode()
    #
    return encoded_name


### ref: [RFC 1035 Section 3.2.1](https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.1)
def input_record(input_type, index = 0):
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
    if index >= 1:
        print(f"#{ index }")
    fleids = re.sub(r"\s+", " ", input(f"please input { input_type } record: ")).split(" ")
    print()
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
def input_a_record(index = 0):
    """
    Parameters
    ----------
    index: int

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
    (owner_name, ttl, class_code, record_type, rdata) = input_record("A", index)
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


### ref: [RFC 1035 Section 3.3.11](https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.11)
def input_ns_record(index = 0):
    """
    Parameters
    ----------
    index: int

    Returns
    -------
    owner_name: str
    ttl: int
    class_code: int
    record_type: int
    nsd_name: str
    """
    NS_RDATA_FIELDS = 1
    #
    (owner_name, ttl, class_code, record_type, rdata) = input_record("NS", index)
    if len(rdata) < NS_RDATA_FIELDS:
        print("Invalid. A record format is: <owner_name> <ttl> <class_code> <record_type> <nsd_name>")
        sys.exit(-1)
    #
    try:
        nsd_name = rdata[0]
    except:
        error_handling()
    #
    return (owner_name, ttl, class_code, record_type, nsd_name)


### ref: [RFC 4034 Section 5.1](https://datatracker.ietf.org/doc/html/rfc4034#section-5.1)
def input_ds_record(index = 0):
    """
    Parameters
    ----------
    index: int

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
    (owner_name, ttl, class_code, record_type, rdata) = input_record("DS", index)
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
        print("Invalid. RRSIG record format is: <owner_name> <ttl> <class_code> <record_type> <target_record_type> <algorithm> <labels> <original_ttl> <expiration> <inception> <keytag> <signer_name> <signature>")
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
def input_dnskey_record(index = 0):
    """
    Parameters
    ----------
    index: int

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
    (owner_name, ttl, class_code, record_type, rdata) = input_record("DNSKEY", index)
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


### ref: [RFC 1035 Section 3.3.11](https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.11)
def encode_ns_rdata(nsd_name):
    """
    Parameters
    ----------
    nsd_name: str

    Returns
    -------
    ns_rdate: byte
    """
    ns_rdata = bytes()
    ns_rdata += encode_name(nsd_name)
    return ns_rdata


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

def validate_ksk_with_ds_digest_main():
    """
    Returns
    -------
    result: boolean
    """
    (owner_name, _, _, _, flag, protocol, algorithm, public_key) = input_dnskey_record()
    (_, _, _, _, keytag, _, digest_type, digest) = input_ds_record()
    #
    dnskey_rdata = encode_dnskey_rdata(flag, protocol, algorithm, public_key)
    #
    if extract_keytag_from_dnskey(dnskey_rdata) != keytag:
        print("Invalid. Keytags do not match.")
        sys.exit(-1)
    #
    result = validate_ds_digest(owner_name, digest_type, digest, dnskey_rdata)
    result_str = "Valid" if result else "Invalid"
    print(f"The KSK is: { result_str }")
    return result


def validate_a_record_signature_main():
    """
    Returns
    -------
    result: boolean
    """
    (_, _, _, _, target_record_type, algorithm, labels, original_ttl, expiration, inception, keytag, signer_name, signature) = input_rrsig_record()
    #
    ### ref: (RFC 4043 Section 3.1.8.1)[https://datatracker.ietf.org/doc/html/rfc4034#section-3.1.8.1]
    rrsig_rdata = encode_rrsig_rdata(target_record_type, algorithm, labels, original_ttl, expiration, inception, keytag, signer_name)
    #
    try:
        num_of_a = int(input("How many A records are there?: "))
        print()
    except:
        error_handling()
    #
    rrs = bytes()
    for index in range(num_of_a):
        (owner_name, _, class_code, record_type, ip_address) = input_a_record(index + 1)
        a_rdata = encode_a_rdata(ip_address)
        rrs += encode_rr(owner_name, record_type, class_code, original_ttl, a_rdata)
    #
    (_, _, _, _, _, _, _, public_key) = input_dnskey_record()
    #
    result = validate_rrsig_signature(algorithm, rrsig_rdata + rrs, signature, public_key)
    result_str = "Valid" if result else "Invalid"
    print(f"The signature of A record is: { result_str }")
    return result


def validate_ns_record_signature_main():
    """
    Returns
    -------
    result: boolean
    """
    (_, _, _, _, target_record_type, algorithm, labels, original_ttl, expiration, inception, keytag, signer_name, signature) = input_rrsig_record()
    #
    ### ref: (RFC 4043 Section 3.1.8.1)[https://datatracker.ietf.org/doc/html/rfc4034#section-3.1.8.1]
    rrsig_rdata = encode_rrsig_rdata(target_record_type, algorithm, labels, original_ttl, expiration, inception, keytag, signer_name)
    #
    try:
        num_of_ns = int(input("How many NS records are there?: "))
        print()
    except:
        error_handling()
    #
    rrs = bytes()
    for index in range(num_of_ns):
        (owner_name, _, class_code, record_type, nsd_name) = input_ns_record(index + 1)
        ns_rdata = encode_ns_rdata(nsd_name)
        rrs += encode_rr(owner_name, record_type, class_code, original_ttl, ns_rdata)
    #
    (_, _, _, _, _, _, _, public_key) = input_dnskey_record()
    #
    result = validate_rrsig_signature(algorithm, rrsig_rdata + rrs, signature, public_key)
    result_str = "Valid" if result else "Invalid"
    print(f"The signature of A record is: { result_str }")
    return result


def validate_ds_record_signature_main():
    """
    Returns
    -------
    result: boolean
    """
    (_, _, _, _, target_record_type, algorithm, labels, original_ttl, expiration, inception, keytag, signer_name, signature) = input_rrsig_record()
    #
    ### ref: (RFC 4043 Section 3.1.8.1)[https://datatracker.ietf.org/doc/html/rfc4034#section-3.1.8.1]
    rrsig_rdata = encode_rrsig_rdata(target_record_type, algorithm, labels, original_ttl, expiration, inception, keytag, signer_name)
    #
    try:
        num_of_ds = int(input("How many DS records are there?: "))
        print()
    except:
        error_handling()
    #
    rrs = bytes()
    for index in range(num_of_ds):
        (owner_name, _, class_code, record_type, keytag, ds_algorithm, digest_type, digest) = input_ds_record(index + 1)
        ds_rdata = encode_ds_rdata(keytag, ds_algorithm, digest_type, digest)
        rrs += encode_rr(owner_name, record_type, class_code, original_ttl, ds_rdata)
    #
    (_, _, _, _, _, _, _, public_key) = input_dnskey_record()
    #
    result = validate_rrsig_signature(algorithm, rrsig_rdata + rrs, signature, public_key)
    result_str = "Valid" if result else "Invalid"
    print(f"The signature of DS record is: { result_str }")
    return


def validate_dnskey_record_signature_main():
    """
    Returns
    -------
    result: boolean
    """
    (_, _, _, _, target_record_type, algorithm, labels, original_ttl, expiration, inception, keytag, signer_name, signature) = input_rrsig_record()
    #
    ### ref: (RFC 4043 Section 3.1.8.1)[https://datatracker.ietf.org/doc/html/rfc4034#section-3.1.8.1]
    rrsig_rdata = encode_rrsig_rdata(target_record_type, algorithm, labels, original_ttl, expiration, inception, keytag, signer_name)
    #
    try:
        num_of_dnskey = int(input("How many DNSKEY records are there?: "))
        print()
    except:
        error_handling()
    #
    rrs = bytes()
    for index in range(num_of_dnskey):
        (owner_name, _, class_code, record_type, dnskey_flag, dnskey_protocol, dnskey_algorithm, dnskey_public_key) = input_dnskey_record(index + 1)
        dnskey_rdata = encode_dnskey_rdata(dnskey_flag, dnskey_protocol, dnskey_algorithm, dnskey_public_key)
        rrs += encode_rr(owner_name, record_type, class_code, original_ttl, dnskey_rdata)
    #
    print("Re-input DNSKEY record which will be used as public key")
    (_, _, _, _, _, _, _, public_key) = input_dnskey_record()
    #
    result = validate_rrsig_signature(algorithm, rrsig_rdata + rrs, signature, public_key)
    result_str = "Valid" if result else "Invalid"
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
0) Extract Key Tag from ZSK/KSK
---
1) Verify signature of DNSKEY record with KSK
2) Verify signature of DS record with ZSK
3) Verify KSK with the digest of DS record
4) Verify signature of A record with ZSK
5) Verify signature of NS record with ZSK
"""
def main():
    print(MENU)
    try:
        select = int(input("Choose one of them: "))
        print()
    except:
        error_handling()
    #
    if select == 0:
        extract_keytag_from_dnskey_main()
    elif select == 1:
        validate_dnskey_record_signature_main()
    elif select == 2:
        validate_ds_record_signature_main()
    elif select == 3:
        validate_ksk_with_ds_digest_main()
    elif select == 4:
        validate_a_record_signature_main()
    elif select == 5:
        validate_ns_record_signature_main()
    else:
        print("Invalid. You chose an unsupport menu.")
    return


if __name__ == "__main__":
    main()
    sys.exit(0)


""" TEST RECORD DATA

. 172800 IN DNSKEY 256 3 8 AwEAAc0SunbHdS0KFEyZbYII/+tzsrNzIwurKxmJA+0fhAYlTPA/5LrM GkGEqvvufzM0w/CaVtdm5eWkZYQcsoSKT5bycx0C4jxnLEb3ZiZUQSqu 1rWcKGF1fj/GyDWLkOu7a5h3el+gPmglj/4l4V31ugNYfqYq84vCB+3D 6Sodrd+85KyonnzWJ8cS7aZ57x0d0sGqsAKA+6tRnIXjVNVe7Ro5xJuz 8IR7rOxdzfuRLriN+Z00EL3U5E7s9SISU/hDh7Q7N70W1mLMc1o2+tCR GjEWrw4wmCWMzc1kegbLES/dUOWFvPjJz0+AEeWDhd2GqtXk02BzAhdf eIAEIv68FTs=
. 172800 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3 +/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kv ArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF 0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+e oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfd RUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwN R1AkUTV74bU=
. 172800 IN RRSIG DNSKEY 8 0 172800 20241201000000 20241110000000 20326 . qt8zpbIcJohyfnFxwgMO9lDmZb7FucLDQ02WBcxZLZ2RCyL0JFy4lR8c E4bCEHfMmIVnST+bBTOgKGnXb0gUVMaLeks19V2zpOLQW091g3gzkEGN IPfFepjnOpR6HUsZG856e4vJqT8OPXTT0V+E3b7N9ulzkOr5KesT02hA IA0dAMNLfeFzlM38L/GUAao9REcaaYfn8TwG7fET/eQSAUk2Z8aI+xkx bjYdRGjHblc8aJKOo5oHQCh1PY693pjJkBf/SzzMmU91tg4nrWHPoJrc 45FBi5bqQ1/LvAB7B+/HDQPKIakHxxWmZ+hSmDp0Yn6e3B9ppWAffdaC kJj7gg==

. 484002 IN NS a.root-servers.net.
. 484002 IN NS b.root-servers.net.
. 484002 IN NS c.root-servers.net.
. 484002 IN NS d.root-servers.net.
. 484002 IN NS e.root-servers.net.
. 484002 IN NS f.root-servers.net.
. 484002 IN NS g.root-servers.net.
. 484002 IN NS h.root-servers.net.
. 484002 IN NS i.root-servers.net.
. 484002 IN NS j.root-servers.net.
. 484002 IN NS k.root-servers.net.
. 484002 IN NS l.root-servers.net.
. 484002 IN NS m.root-servers.net.
. 484002 IN RRSIG NS 8 0 518400 20241124050000 20241111040000 61050 . jgQ3G0mud6ZR/ukMJo8xq1bGbd66kkTxf7tURZEfbSAxZMdKlEh8m0GP yd7xdeR1gFUQbqc8+B0gx1zmzbCe2TrovzyZejL8qTWJDKL/+nrT6qR2 6zYgWh075gDsFYYZiFybxxKQs6j3atsun0CEefw/0KxDtNdh/I3qUgSd 4a0NpwSB3VUkeM1418vpQo7IHacDTACDw9VB7L+JeaOlNARY5q6UptJD fkTT2vLdtiWxdDVy/PycbgpeehgibcBSKqi0YyqwoJ5NJdleR8NFrP5K kFUiCSlDYxQ5Q/ZpeoAS4lm7wJzrVbEHLRam3gpJXCfGusLfuB7bY8z+ v8mBPw==

com. 86400 IN DS 19718 13 2 8ACBB0CD28F41250A80A491389424D341522D946B0DA0C0291F2D3D7 71D7805A
com. 86400 IN RRSIG DS 8 1 86400 20241124170000 20241111160000 61050 . df091JsunjSyd2Rh1RVpH07FPCugkarUWf362yFQnx85oAK9hKqgSSIc MrGPe1a9Cukb841p+MFzP/7fQ+WL5P787w6oQ1K6/pYFNLj9Ueem/Umg lzf1nQpDD0X+X2zwF7bQ6WKFjLZ0NjmELCmtZOg/vL4ZfZ1jI9vbYnGM dq8Qdt6+pg2cdUmWcBBoNFPDzVRSKxkC4g8XUooka8qrWaGWZ+aYUHzx e5hVHVtQMcoOKefNu+qGqUln//uuudPHsnULDACSJtmcsnJAsVrp5VSM B46/2KVpdaX1ITFbvxclGv+fzwuvMtLO2X7OKzddXZ83xjeBOgYdELJ2 OynhSA==

com. 86400 IN DNSKEY 256 3 13 uugEQOG7/3zv3rVGq43NQTqfmZxWn4fMIpi6ph7JKEvTRwhtw3aIV4dS k+fgpFFmORrKNznT7AIuJKy6P/Mi1Q==
com. 86400 IN DNSKEY 257 3 13 tx8EZRAd2+K/DJRV0S+hbBzaRPS/G6JVNBitHzqpsGlz8huE61Ms9ANe 6NSDLKJtiTBqfTJWDAywEp1FCsEINQ==
com. 86400 IN RRSIG DNSKEY 13 1 86400 20241118150235 20241103145735 19718 com. IZbO0s7a+wpAIXAVF4oLxATiRwOM0yitR7+tBihVCf8FmlDVQf92fK1w USuggYfJ+d+25B9Zz5bYqL/DQt3bmw==

com. 172800 IN NS a.gtld-servers.net.
com. 172800 IN NS b.gtld-servers.net.
com. 172800 IN NS c.gtld-servers.net.
com. 172800 IN NS d.gtld-servers.net.
com. 172800 IN NS e.gtld-servers.net.
com. 172800 IN NS f.gtld-servers.net.
com. 172800 IN NS g.gtld-servers.net.
com. 172800 IN NS h.gtld-servers.net.
com. 172800 IN NS i.gtld-servers.net.
com. 172800 IN NS j.gtld-servers.net.
com. 172800 IN NS k.gtld-servers.net.
com. 172800 IN NS l.gtld-servers.net.
com. 172800 IN NS m.gtld-servers.net.
com. 172800 IN RRSIG NS 13 1 172800 20241117002547 20241109231547 29942 com. lpS1jaImw6HG5hSnYpgnNNmF1Ngv1Gz+WyL1SVfM+Yoo88qd56UWH6WG VP26ZAKq2A4fVBmimK2Ny0aWZOX3gA==

example.com. 86400 IN DS 370 13 2 BE74359954660069D5C63D200C39F5603827D7DD02B56F120EE9F3A8 6764247C
example.com. 86400 IN RRSIG DS 13 2 86400 20241119012518 20241112001518 29942 com. xDTV+GSyIuGyeLLin8fd12iXoPr5EayvZ2L6xdC2YMjGKkxQksIS7e26 iSR20EVYMPTmdA5Igdb0Eaf+XoA7Ng==

example.com. 3600 IN DNSKEY 256 3 13 OtuN/SL9sE+SDQ0tOLeezr1KzUNi77FflTjxQylUhm3V7m13Vz9tYQuc SGK0pyxISo9CQsszubAwJSypq3li3g==
example.com. 3600 IN DNSKEY 256 3 13 ai2pvpijJjeNTpBu4yg6T375JqIStPtLABDTAILb+f4J7XpofUNXGQn6 FpQvZ6CARWn2xQapbjGtDRjTf4qYxg==
example.com. 3600 IN DNSKEY 257 3 13 kXKkvWU3vGYfTJGl3qBd4qhiWp5aRs7YtkCJxD2d+t7KXqwahww5IgJt xJT2yFItlggazyfXqJEVOmMJ3qT0tQ==
example.com. 3600 IN RRSIG DNSKEY 13 2 3600 20241202171948 20241111065631 370 example.com. gai6TfgY0Xc9OUoE0UgumfKQOnHZuvXzVnznkc806m8oetr6pyoVi6tf PIrUnFHqL7VgQ78dsW5JsXrFmt332A==

example.com. 3600 IN A 93.184.215.14
example.com. 3600 IN RRSIG A 13 2 3600 20241117173922 20241027165426 42464 example.com. i547XFAHRMLksexkC9j18YvDcsDSE1SNVorFihK5mYWJ /wG4zqh3ELOJ/HiVXQ0hdmgFvMj16XbPQJkqIJjI1Q==

---

iij.ad.jp. 1292 IN DS 48472 8 2 7E73B74DD5BF727B67C7D62A2D8CA3C02FECF00DBC2848DB7C57A99B 515D0D0E

iij.ad.jp. 1488 IN DNSKEY 256 3 8 AwEAAbdSiZ0RxmtsZUbE1v5kJWi3tXYBQYmZZmYVyw5QgSI7zSoOIcdW 2NoSX+rarklHdnBZKHgBE/lylRxxEi5pGQaJFLVEMBbUo5leb9nmikWG +GxWJL6dZic5LIt3hyAZ0r9jNJN/apzbQh16X41X8gE4lMymlMDXRf6W SbfKReW9
iij.ad.jp. 1488 IN DNSKEY 257 3 8 AwEAAfByl5y3fBxdJ+ALSWRc55A8Dp8ZBr+7JxJcml1Ys/bmvVRvG72e s+DvOBR1jjS1l1j74e2eP89ClInWPVajZKc4AX69/btKQznfwC35secx Jniud6VctkF35xqfVZZnXOetF4+QtJtSYhVNg/hirc7HuSpgnzggqt75 X2qaA6THYR9oVBuV+Bu/CrN+KV3qs//r0Fcr7b6Q2VMRWWZe+uqFy5ij PUQq+nXGHgpYxY1CgWH4wRK8WWzUXzE55otuajaBhTH3pi7tz9nKqi7J gBs/l051Ezg7rFfrj857kprMWUu5oacLs3WfZOA0T6fx8aO792HkgEEr Th0LvVWVMqU=
iij.ad.jp. 2176 IN RRSIG DNSKEY 8 3 86400 20201217151006 20201117151006 48472 iij.ad.jp. IvflOJImlu9iSR7LO80wv9o4FJsmy0UDB1gmIPzbqaTIa+z9ePG+tSYa z6HEck75SWWeZeXM0zbAuYX5/had7qTh+IFhO1m9GcIg9+KTdHrKR9jP 9DuVvk3IGJXTpO/L5fPfwsFPrSqfktO9ug6mnwrXshqKIk16NcTggpdd k22Wt1ksDDgZ/61p9j5Zk0CTR2t8/I/rwCcWc7zUsyLAF2rbcBufpsn/ PEz/qPnCgFRjSRkeDln0MaX9NH+48A5vYbthLhtGgc2pviIACc6EYaw2 HSggSD2zR1mJLy7P4APvgu1ijSKXpgF4SpRmhqeuYLkGMbvKnK87N5LK vL7VKg==

eng-blog.iij.ad.jp. 419 IN A 203.180.155.24
eng-blog.iij.ad.jp. 1347 IN RRSIG A 8 4 86400 20201217151006 20201117151006 5628 iij.ad.jp. ITYLFLnc7s3rB0aZNVSrCsUNBs3vRztF87XjgFHf6Q8yQ2GPFX72s/w5 m5dUDeV/UJBEwB7udTAPxeNarqaoe/Ot0ExkjVpZ2u5zQXdO//ExbmBs 8YX/xCBTJJX6te0odwpJBzFmL2Ecxs6VNm71/xugV2EKIzzeI/vKLJkY Qhg=

---

dnstests.ovh. 2954 IN DNSKEY 256 3 8 AwEAAc9juwZVMUrdjPIxMPuOk+ZnVhv+i16B3TTxj1Ft 5ABDEbiXyfljJopTCQgmJ4EcNDubhZKezTqGsbpaErw8 8yqFwzviv2/U9Mw+Vq1zbS29Hl6XzyWPlnYryXcyVDEw OZlsK0hw6d7A6Xcjjf2srnxpQHpO9pG+etFZxSSEV49j
dnstests.ovh. 2954 IN DNSKEY 257 3 8 AwEAAZ5F0TSR8PWTrADtdlTcuGWBZ1ehOHy7RtX/ZyA6 WQSU+59I8PFWQ6ddD4FX7LfNcaPSd10vjZKmGT9fB8uf IY9xHHrH2zGc6jEI7TkqDOjutVRsBhhis+AO/HDjL9i0 tpyoCX3/wHVZ9U0iOIHaR4+vlVJfja6EvuL4s0zhzaY0 amP1R8af0E1Rcvyi9S6fFOtECZOrqKlwI9OPQneQ2gD4 uXWg97o1kuBvxSg/Ze5NsAIsJu3oShxBPUNmW6hwP8FM tbmft4MqpJ3xiI03FN2t2PwgO3cvCYlyBJRZqo9nqLAz yYheVdoMuBP024bXF1HFDo2n7jZMuDrW7mMfPK8=
dnstests.ovh. 2954 IN RRSIG DNSKEY 8 2 3600 20200925080215 20200826080215 44329 dnstests.ovh. k/huKVd5Skc8PE1CgHl1/MCEjZs6hH1DlLYGHZxG97YK YBSwvWQoXGG6ObZKJYCWVqDJWvdz81K7XHLvK34g3AwB NyI62Aw00GiaJzpFCkKU+jTVPeVvDKpAKGQxPziWCL/4 Buj230YyDm38V4amxAeBOz5FcvD8eDu6XYMx4ygvJ3XF M7zojtsbqwg7IBJPJUURNfpQi8MbJivelXbh2CJACteB 8zd2dsj0eZRTLulC15qr7R7zBQqJ8CVuPAVHBYfy2Nu/ VE2QSe2Q4zzns9TUH/6/g9f8RDMNDhT+Z1lbsaJg9EzH x4bqLfjEjnqhrzdS/Fc02e7bILe9YGQ5SQ==

dnstests.ovh. 3600 IN A 213.186.33.5
dnstests.ovh. 3600 IN RRSIG A 8 2 3600 20200925080215 20200826080215 50238 dnstests.ovh. AUz7u4Sq0EkSUq5kR0beowmMuscbzGdb3NI/OhCG8Ow0Z3CqgG0/94eR 6pbG7YJwvCFBU1bQDklLYEfc4mg41VeAVY4xPSv0O76/hEZsVKcBOGlT nKy3wV4ft8ykV1Jl+5q2eJAaZRoBSvHuRItbM2HCyghhDW0gKBy5rqOq BlM=

"""
