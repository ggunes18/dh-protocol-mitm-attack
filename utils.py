import os
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import Encoding, ParameterFormat, load_der_parameters
from hashlib import sha256
from Crypto.Cipher import AES
import json
from base64 import b64encode, b64decode

def get_or_create_parameters():
    # if parameters already created by previous user
    if os.path.exists("dh_parameters.der"):
        with open("dh_parameters.der", "rb") as f:
            serialized_parameters = f.read()
        # read parameters
        parameters = load_der_parameters(serialized_parameters)
    # if no parameters are created yet
    else:
        # generate parameters
        parameters = dh.generate_parameters(generator=5, key_size=1024)
        serialized_parameters = parameters.parameter_bytes(
            encoding=Encoding.DER,
            format=ParameterFormat.PKCS3
        )
        # write parameters into dh_parameters.der file for the next user
        with open("dh_parameters.der", "wb") as f:
            f.write(serialized_parameters)
    return parameters


def generate_dh_secrets(parameters):
    return parameters.private_numbers().x


def generate_dh_public(parameters):
    return parameters.public_key().public_numbers().y


def write_to_txt_file(value, file_name, pad_char="\n", pad_length=1):
    if os.path.exists(file_name):
        with open(file_name, "a") as f:
            f.write(str(value) + pad_char*pad_length)
    else:
        with open(file_name, "w") as f:
            f.write(str(value) + pad_char*pad_length)


def read_dh_public_value(public_value, file_name):
    result = []
    if os.path.exists(file_name):
        with open(file_name) as f:
            for line in f:
                line = line.strip()
                if line != str(public_value):
                    result.append(line)
    return result[0] if result else None


def read_last_message(file_name):
    result = None
    if os.path.exists(file_name):
        with open(file_name, "r") as f:
            lines = f.readlines()
            if lines:
                result = lines[-1].strip()
    return result


def encrypt_message(key, message):
    message = message.encode('utf-8')
    cipher = AES.new(key, AES.MODE_CTR)
    ct_bytes = cipher.encrypt(message)
    nonce = b64encode(cipher.nonce).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'nonce':nonce, 'ciphertext':ct})
    return result


def decrypt_message(key, ciphertext):
    try:
        b64 = json.loads(ciphertext)
        nonce = b64decode(b64['nonce'])
        ct = b64decode(b64['ciphertext'])
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        pt = cipher.decrypt(ct)
        pt = pt.decode('utf-8')
        return pt
    except (ValueError, KeyError):
        print("Incorrect decryption")