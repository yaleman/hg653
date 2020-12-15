#!/usr/bin/env python3

# originally sourced from hg658c.wordpress.com
"""
To decrypt encrypted values in the config, use 
echo -n "Lp0xkiAANwcYpVPbI3D/Mg==" | base64 -d | openssl enc -d -aes-128-cbc \
-K DBAF3361E81DA0EF5358A1929FC90A80 -iv 629EA150533376741BE36F3C819E77BA -nopad
"""

import sys
import os
from binascii import hexlify, unhexlify 
try:
    from Crypto.Cipher import AES
    from Crypto.Hash import MD5
    from Crypto.Util import number
except ImportError:
	print("Error loading dependency, install pycrypto package before trying again")
	sys.exit(1)
import zlib

RSA_D = ("ABADA5BCEE9A32B45696E6C99A0B9E68"
         "45F72D94486DFA761DB59B3D8576B72D"
         "A7CE4B434898BEEB7E3B114C7CB4AE95"
         "8593899F6572CE060CC7AE3FC7733DE0"
         "02AE9F2164765C3260DBB3F1D9920BDB"
         "BB235E96036864C05695B86950CAB6C9"
         "E3524583A537239335381AD8240FB311"
         "AFDD3DCAF1F68112D556964ECB568421")

RSA_N = ("B597A54F66CA6332972D9986AB87F741"
         "B9BBA24A130612C01620EAE53DD0F993"
         "9E9F53440549ED7B7FC2B739B33A7735"
         "E42A1FC90F6A9C17E4A7A57EDF733624"
         "5A4F67DFD757820782264D7CBA8DA067"
         "6E5661968EF8510BB88FEF7E2320A657"
         "CCB5A75E28C1ACE7FC0B3DD15C0051FC"
         "A343B42464935A0B31D2C2F904767CE3")

RSA_E = "010001"         

SIG_TEMPLATE = ("0001ffffffffffffffffffffffffffff"
                "ffffffffffffffffffffffffffffffff"
                "ffffffffffffffffffffffffffffffff"
                "ffffffffffffffffffffffffffffffff"
                "ffffffffffffffffffffffffffffffff"
                "ffffffffffffffffffffffffff003020"
                "300c06082a864886f70d020505000410")

AES256CBC_KEY = "1AAAB4A730B23E1FC8A1D59C79283A228B78410ECC46FA4F48EB1456E24C5B89"
AES256CBC_IV  = "D1FE7512325C5713D362D332AFA3644C"

XML_VERSION_STRING = b'<?xml version="1.0" ?>'

def print_usage():
    print("Usage : " + sys.argv[0] + " {encrypt | decrypt} input_file output_file")
    sys.exit(1)

def load_config(config_file):
    if os.path.isfile(config_file):
        with open(config_file, "rb") as cf:
          return cf.read()
    else:
        print("Config file not found..exiting")
        sys.exit(1)

def save_to_file(dest_file, data):
    with open(dest_file,"wb") as fh:
        fh.write(data)

def get_md5_hash_from_sig(sig):
    sig_int = int(hexlify(sig),16)
    rsa_n = int(RSA_N,16)
    dec_sig_as_int = pow(sig_int, 0x10001, rsa_n );
    decrypted_sig = number.long_to_bytes(dec_sig_as_int, 128)
    target_md5 = hexlify(decrypted_sig)[-64:]
    return target_md5

def calc_actual_md5_hash(enc_config_body):
    md5 = MD5.new()
    md5.update(enc_config_body)
    actual_md5_sig = md5.hexdigest()
    actual_md5_sig = str.encode(actual_md5_sig)
    return actual_md5_sig

def decrypt_config(input_file, output_file):
    enc_config=load_config(input_file)

    print("Decrypting...")
    iv = unhexlify(AES256CBC_IV)
    key= unhexlify(AES256CBC_KEY)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        decrypted_data = cipher.decrypt(enc_config)
        decompressed_data=""

        decompressed_data = zlib.decompress(decrypted_data)
    except:
        print("Bad config file...exiting")
        sys.exit(1) 

    config_text = decompressed_data[:-0x80]
    actual_md5_hash = calc_actual_md5_hash(config_text)

    print("Verifying signature...")
    sig = decompressed_data [-0x80:]
    sig_int = int(hexlify(sig),16)
    rsa_n = int(RSA_N,16)
    dec_sig_as_int = pow(sig_int, 0x10001, rsa_n );
    decrypted_sig = number.long_to_bytes(dec_sig_as_int, 128)
    target_md5_hash = hexlify(decrypted_sig)[-32:]

    if (actual_md5_hash == target_md5_hash):
        print("Signature ok...")        
    else:
        print("Signature not ok...exiting")
        sys.exit(1)

    config_text = config_text[:-1]
    check_config(config_text)

    print("Saving decrypted config to " + output_file + "...")
    save_to_file(output_file, config_text)

def check_config(new_config_file):
    if not new_config_file.startswith(XML_VERSION_STRING):
        print("Not a valid config file...exiting")
        sys.exit(1)

def encrypt_config(input_file, output_file):
    new_config_data=load_config(input_file)
    check_config(new_config_data)
    new_config_data += '\0'.encode()

    print("Calculating MD5 hash...")
    h = MD5.new()
    h.update(new_config_data)
    actual_md5_sig = h.hexdigest()

    sig = SIG_TEMPLATE + actual_md5_sig;

    print("Adding Signature...")
    sig_int = int(sig,16)
    rsa_d = int(RSA_D,16)
    rsa_n = int(RSA_N,16)
    enc_sig_int = pow(sig_int, rsa_d, rsa_n);
    encrypted_sig = number.long_to_bytes(enc_sig_int, 128)
    new_config_data = new_config_data + encrypted_sig

    print("Compressing config...")
    compressed_data = zlib.compress(new_config_data, 9)

    padding_amount = len(compressed_data) % 16
    print("" + str(padding_amount) + " bytes padding needed")
    print("Adding padding...")
    compressed_data=compressed_data + b'\0'*(16-padding_amount)

    print("Encrypting config...")
    iv = unhexlify(AES256CBC_IV)
    key= unhexlify(AES256CBC_KEY)
    aes = AES.new(key, AES.MODE_CBC, iv)
    enc_new_config = aes.encrypt(compressed_data)

    print("Saving encrypted config to " + output_file + "...")
    save_to_file(output_file, enc_new_config)

def main():
    if len(sys.argv) < 4:
        print_usage()

    input_file = sys.argv[2]
    output_file = sys.argv[3]
    command = sys.argv[1]

    if (command == "encrypt"):
        encrypt_config(input_file, output_file)
    elif (command == "decrypt"):
        decrypt_config(input_file, output_file) 
    else: 
        print_usage()


if __name__ == "__main__":
    main()