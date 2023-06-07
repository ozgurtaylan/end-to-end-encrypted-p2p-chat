import os
import traceback

import rsa
import json
import secrets
import random
import string
import hashlib
from Crypto.Cipher import AES
import json
from base64 import b64encode, b64decode
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hmac
import configs as conn
from configs import get_current_time
import os


def generate_pb_pr_keys(pb_pr_author):
    try:
        pb, pr = rsa.newkeys(1024)
        pb_file_name = os.path.join(pb_pr_author + "_database", pb_pr_author + "_public_key.pem")
        pr_file_name = os.path.join(pb_pr_author + "_database", pb_pr_author + "_private_key.pem")
        with open(pb_file_name, "wb") as f:
            f.write(pb.save_pkcs1(format="PEM"))
        with open(pr_file_name, "wb") as f:
            f.write(pr.save_pkcs1(format="PEM"))
        print(f"[{get_current_time()}]: [Public & Private Keys Generated for {pb_pr_author}]")
    except Exception as e:
        print(e)


# Caution! Return type is not bytes
def get_public_key(public_key_author):
    try:
        pb_file_name = os.path.join(public_key_author + "_database", public_key_author + "_public_key.pem")
        with open(pb_file_name, "rb") as f:
            pb = rsa.PublicKey.load_pkcs1(f.read())
        return pb
    except Exception as e:
        return None


# Caution! Return type is not bytes
def get_private_key(private_key_author):
    try:
        pr_file_name = os.path.join(private_key_author + "_database", private_key_author + "_private_key.pem")
        with open(pr_file_name, "rb") as f:
            pr = rsa.PrivateKey.load_pkcs1(f.read())
        return pr
    except Exception as e:
        return None


def get_certificate(author_name):
    try:
        cf_file_name = os.path.join("server_database", author_name + "_certificate.txt")
        with open(cf_file_name, "rb") as f:
            certificate = f.read()
        return certificate
    except Exception as e:
        return None


def save_certificate(certificate, author_name):
    try:
        cf_file_name = os.path.join("server_database", author_name + "_certificate.txt")
        with open(cf_file_name, "wb") as f:
            f.write(certificate)
    except Exception as e:
        print(e)


def encrypt_with_rsa_public(message, pb_key):
    if isinstance(message, bytes):
        message = message
    else:
        message = message.encode()
    try:
        encrypted_message = rsa.encrypt(message, pb_key)
        return encrypted_message
    except Exception as e:
        print(traceback.format_exc())
        print(e)


def decrypt_with_rsa_private(encrypted_message, pr_key):
    try:
        decrypted_message = rsa.decrypt(encrypted_message, pr_key)
        return decrypted_message
    except Exception as e:
        print(e)


def get_hash_message_digest(message):
    if not isinstance(message, bytes):
        message = message.encode(conn.FORMAT)
    digest = rsa.compute_hash(message, 'SHA-256')
    return digest


def create_digital_signature(message, private_key_author):
    if isinstance(message, bytes) is False:
        message = message.encode(conn.FORMAT)

    try:
        pr = get_private_key(private_key_author=private_key_author)
        hash = get_hash_message_digest(message)
        signature = rsa.sign_hash(hash, pr, 'SHA-256')
        return signature
    except Exception as e:
        print(e)


def verify_digital_signature(message, signature, author_name):
    if isinstance(message, bytes) is False:
        message = message.encode(conn.FORMAT)

    try:
        pb = get_public_key(author_name)
        res = rsa.verify(message, signature, pb)
        if res == "SHA-256":
            return True
    except Exception as e:
        if isinstance(e, rsa.pkcs1.VerificationError):
            return False
        else:
            return False


def generate_symmetric_key(symmetric_key_author: str):
    filename = symmetric_key_author + "_symmetric_key.txt"
    foldername = symmetric_key_author + "_database"
    path = os.path.join(foldername, filename)
    # Generate a 32-byte (256-bit) symetric key
    key = secrets.token_bytes(32)
    # Save the key to the file
    with open(path, "wb") as key_file:
        key_file.write(key)
    return key


def get_symmetric_key(symmetric_key_author: str):
    # use the folder [symetric_key_author]_database
    # to store the symetric key, file name is [symetric_key_author]_symetric_key.txt
    filename = symmetric_key_author + "_symmetric_key.txt"
    foldername = symmetric_key_author + "_database"
    path = os.path.join(foldername, filename)
    key = ""
    # Read the key from the file
    with open(path, "rb") as key_file:
        key = key_file.read()

    return key


def generate_random_text(length):
    letters = string.ascii_letters
    text = ''.join(random.choice(letters) for _ in range(length))
    return text


def aes_cbc_encryption(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    padded = pad(message, AES.block_size)
    ct_bytes = cipher.encrypt(padded)
    return cipher.iv, ct_bytes


def aes_cbc_decryption(iv, ciphertext, key):
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_pt = cipher.decrypt(ciphertext)
        pt = unpad(padded_pt, AES.block_size)
        return pt
    except (ValueError, KeyError):
        print(traceback.format_exc())
        print(f"[{get_current_time()}]: Error: Incorrect decryption")


def generate_mac(message, symmetric_key):
    hmac_sha256 = hmac.new(symmetric_key, message, hashlib.sha256)
    return hmac_sha256.digest()


def verify_mac(message, mac, symmetric_key):
    hmac_sha256 = hmac.new(symmetric_key, message, hashlib.sha256)
    return hmac.compare_digest(mac, hmac_sha256.digest())


def generate_nonce(length=16):
    nonce = os.urandom(length)
    return nonce
