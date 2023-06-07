import socket
from configs import ConnectionConfigs as conn
from configs import DatabaseConfigs as db
from configs import get_current_time
from configs import yellow_text, green_text, red_text, blue_text, purple_text
import base64
import crypto
import json
from colorama import Fore, Back, Style

user1_public_key = None
user1_private_key = None
user1_certificate = None
user2_public_key = None


def get_certification_from_server():
    SERVER = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    SERVER.connect(conn.ADDR)

    global user1_public_key
    user1_public_key = crypto.get_public_key(public_key_author=db.USER1_NAME)

    global user1_private_key
    user1_private_key = crypto.get_private_key(private_key_author=db.USER1_NAME)

    pub_key = user1_public_key.save_pkcs1()
    msg = {"username": db.USER1_NAME,
           "pub_key": pub_key.decode(conn.FORMAT)}

    msg = json.dumps(msg).encode(conn.FORMAT)
    SERVER.send(msg)

    certificate = SERVER.recv(conn.BUFF_SIZE)
    global user1_certificate
    user1_certificate = certificate

    print(
        f"user1_public_key: {user1_public_key.save_pkcs1()}, user1_certificate: {user1_certificate}\ntype of user1_certificate: {type(user1_certificate)}, type of user1_public_key: {type(user1_public_key.save_pkcs1())}")

    if crypto.verify_digital_signature(message=pub_key, signature=certificate, author_name=db.SERVER_NAME):
        print(f"[{get_current_time()}]: [CERTIFICATE IS CORRECT] -> saving...")
        crypto.save_certificate(certificate=certificate, author_name=db.USER1_NAME)
    else:
        print(f"[{get_current_time()}]: Certification got error")


def create_message_with_certificate(message, symmetric_key):
    message = json.dumps(
        {"message": message, "certificate": base64.b64encode(user1_certificate).decode(conn.FORMAT)}).encode(
        conn.FORMAT)

    print(f"[{get_current_time()}]: [CREATED MESSAGE WITH CERTIFICATE]")

    mac = crypto.generate_mac(message, symmetric_key)
    print(f"[{get_current_time()}]: [GENERATED MAC (HMAC)]")
    mac = crypto.create_digital_signature(mac, db.USER1_NAME)
    print(f"[{get_current_time()}]: [APPLIED DIGITAL SIGNATURE ON MAC (RSA)]")

    content_of_ks = json.dumps(
        {"message": message.decode(conn.FORMAT), "mac": base64.b64encode(mac).decode(conn.FORMAT)}).encode(conn.FORMAT)
    # encrypt message with symmetric key
    iv, ciphertext = crypto.aes_cbc_encryption(content_of_ks, symmetric_key)
    print(f"[{get_current_time()}]: [ENCRYPTED MESSAGE WITH SYMMETRIC KEY (AES-CBC)]")

    encrypted_ks = crypto.encrypt_with_rsa_public(symmetric_key, user2_public_key)
    msg_dict = {"iv": base64.b64encode(iv).decode(conn.FORMAT),
                "ciphertext": base64.b64encode(ciphertext).decode(conn.FORMAT),
                "encrypted_ks": base64.b64encode(encrypted_ks).decode(conn.FORMAT)}
    return json.dumps(msg_dict).encode(conn.FORMAT)

def create_message(message, symmetric_key):
    message = json.dumps({"message": message}).encode(conn.FORMAT)
    print(f"[{get_current_time()}]: [CREATED MESSAGE]")

    mac = crypto.generate_mac(message, symmetric_key)
    print(f"[{get_current_time()}]: [GENERATED MAC (HMAC)]")
    mac = crypto.create_digital_signature(mac, db.USER1_NAME)
    print(f"[{get_current_time()}]: [APPLIED DIGITAL SIGNATURE ON MAC (RSA)]")

    content_of_ks = json.dumps(
        {"message": message.decode(conn.FORMAT), "mac": base64.b64encode(mac).decode(conn.FORMAT)}).encode(conn.FORMAT)
    # encrypt message with symmetric key
    iv, ciphertext = crypto.aes_cbc_encryption(content_of_ks, symmetric_key)
    print(f"[{get_current_time()}]: [ENCRYPTED MESSAGE WITH SYMMETRIC KEY (AES-CBC)]")

    msg_dict = {"iv": base64.b64encode(iv).decode(conn.FORMAT),
                "ciphertext": base64.b64encode(ciphertext).decode(conn.FORMAT)}
    return json.dumps(msg_dict).encode(conn.FORMAT)


def receive_message_with_certificate(msg, symmetric_key):
    msg_in_str = msg.decode(conn.FORMAT)
    msg_dict = json.loads(msg_in_str)
    iv = base64.b64decode(msg_dict['iv'].encode(conn.FORMAT))
    ciphertext = base64.b64decode(msg_dict['ciphertext'].encode(conn.FORMAT))

    # decrypt ciphertext
    content_of_ks = crypto.aes_cbc_decryption(iv, ciphertext, symmetric_key)
    print(f"[{get_current_time()}]: [DECRYPTED MESSAGE WITH SYMMETRIC KEY (AES-CBC)]")
    content_of_ks = content_of_ks.decode(conn.FORMAT)
    content_of_ks = json.loads(content_of_ks)

    content_of_mac = content_of_ks['message'].encode(conn.FORMAT)
    mac = base64.b64decode(content_of_ks['mac'].encode(conn.FORMAT))
    calculated_mac = crypto.generate_mac(content_of_mac, symmetric_key)
    mac_verification = crypto.verify_digital_signature(message=calculated_mac, signature=mac, author_name=db.USER2_NAME)
    print(f"[{get_current_time()}]: {green_text('[VERIFIED MAC (HMAC)]')}")

    return [json.loads(content_of_mac.decode(conn.FORMAT))['message'], base64.b64decode(
        json.loads(content_of_mac.decode(conn.FORMAT))['certificate'].encode(conn.FORMAT)), mac_verification]

def receive_message(msg, symmetric_key):
    msg_in_str = msg.decode(conn.FORMAT)
    msg_dict = json.loads(msg_in_str)
    iv = base64.b64decode(msg_dict['iv'].encode(conn.FORMAT))
    ciphertext = base64.b64decode(msg_dict['ciphertext'].encode(conn.FORMAT))

    # decrypt ciphertext
    content_of_ks = crypto.aes_cbc_decryption(iv, ciphertext, symmetric_key)
    print(f"[{get_current_time()}]: [DECRYPTED MESSAGE WITH SYMMETRIC KEY (AES-CBC)]")
    content_of_ks = content_of_ks.decode(conn.FORMAT)
    content_of_ks = json.loads(content_of_ks)

    content_of_mac = content_of_ks['message'].encode(conn.FORMAT)
    mac = base64.b64decode(content_of_ks['mac'].encode(conn.FORMAT))
    calculated_mac = crypto.generate_mac(content_of_mac, symmetric_key)
    mac_verification = crypto.verify_digital_signature(message=calculated_mac, signature=mac, author_name=db.USER2_NAME)
    print(f"[{get_current_time()}]: {green_text('[VERIFIED MAC (HMAC)]')}")

    return [json.loads(content_of_mac.decode(conn.FORMAT))['message'], mac_verification]

def handle_client(SERVER):
    while True:
        # send syn to user2 server
        SERVER.connect(conn.USER2_ADDR)
        SERVER.send("SYN".encode(conn.FORMAT))
        print(f"[{get_current_time()}]: {yellow_text('--> [SYN SENT TO ' + str(conn.USER2_ADDR) + ']')}")

        # wait for syn-ack from user2 server
        msg = SERVER.recv(conn.BUFF_SIZE).decode(conn.FORMAT)
        print(f"[{get_current_time()}]: {yellow_text('<-- [RECEIVED MESSAGE FROM ' + str(conn.USER2_ADDR) + ']: ' + msg)}")

        if msg == "SYN-ACK":
            # send ack to user2 server
            SERVER.send("ACK".encode(conn.FORMAT))
            print(f"[{get_current_time()}]: {yellow_text('--> [ACK SENT TO ' + str(conn.USER2_ADDR) + ']')}")

            global user1_private_key
            user1_private_key = crypto.get_private_key(private_key_author=db.USER1_NAME)

            global user1_public_key
            user1_public_key = crypto.get_public_key(public_key_author=db.USER1_NAME)

            global user2_public_key
            user2_public_key = crypto.get_public_key(public_key_author=db.USER2_NAME)

            global user1_certificate
            user1_certificate = crypto.get_certificate(author_name=db.USER1_NAME)

            symmetric_key = crypto.generate_symmetric_key(db.USER1_NAME)

            SERVER.send(create_message_with_certificate("Hello", symmetric_key))
            print(f"[{get_current_time()}]: {yellow_text('--> [HELLO AND CERTIFICATE SENT TO ' + str(conn.USER2_ADDR) + ']')}")

            # receive message from user2 server
            msg = SERVER.recv(conn.BUFF_SIZE)
            print(f"[{get_current_time()}]: {yellow_text('<-- [RECEIVED MESSAGE FROM ' + str(conn.USER2_ADDR) + ']: ' + str(msg))}")
            message_content = receive_message_with_certificate(msg, symmetric_key)
            message = message_content[0]
            certificate = message_content[1]
            mac_verification = message_content[2]

            if crypto.verify_digital_signature(message=user2_public_key.save_pkcs1(), signature=certificate,
                                               author_name=db.SERVER_NAME):
                print(f"[{get_current_time()}]: {green_text('[CERTIFICATE IS VALID]')}")
                if mac_verification:
                    print(f"[{get_current_time()}]: {yellow_text('MESSAGE FROM ' + str(conn.USER2_ADDR) + ']: ' + str(base64.b64decode(message.encode(conn.FORMAT))))}")
                    nonce = base64.b64decode(message.encode(conn.FORMAT))
                    SERVER.send(create_message(base64.b64encode(crypto.create_digital_signature(nonce, db.USER1_NAME)).decode(conn.FORMAT), symmetric_key))
                    print(f"[{get_current_time()}]: {yellow_text('--> [ENCRYPTED NONCE SENT TO ' + str(conn.USER2_ADDR) + ']')}")

                    msg = SERVER.recv(conn.BUFF_SIZE)
                    message_content = receive_message(msg, symmetric_key)
                    message = message_content[0]
                    mac_verification = message_content[1]

                    if mac_verification:
                        if message == "ACK":
                            print(f"[{get_current_time()}]: {yellow_text('<-- [ACK RECEIVED FROM ' + str(conn.USER2_ADDR) + ']')}")
                            print(f"[{get_current_time()}]: {green_text('[SESSION ESTABLISHED]')}")
                            print(f"[{get_current_time()}]: {green_text('[STARTING CHAT]')}")
                            while True:
                                # get input from user and send it to user2 server

                                msg = input(f"[{get_current_time()}]: {blue_text('[YOU]: ')}")
                                SERVER.send(create_message(msg, symmetric_key))
                                print(f"[{get_current_time()}]: {yellow_text('--> [MESSAGE SENT TO ' + str(conn.USER2_ADDR) + ']')}")
                                # receive message from user2 server
                                print(f"[{get_current_time()}]: {blue_text('[WAITING FOR MESSAGE]')}")
                                msg = SERVER.recv(conn.BUFF_SIZE)
                                print(f"[{get_current_time()}]: {yellow_text('<-- [RECEIVED MESSAGE FROM ' + str(conn.USER2_ADDR) + ']: ' + str(msg))}")
                                message_content = receive_message(msg, symmetric_key)
                                message = message_content[0]
                                mac_verification = message_content[1]
                                if mac_verification:
                                    print(f"[{get_current_time()}]: {blue_text('[MESSAGE FROM ' + str(conn.USER2_ADDR) + ']: ' + purple_text(message))}")
                                else:
                                    print(f"[{get_current_time()}]: {red_text('[MAC VERIFICATION FAILED]')}")
                                    break
                        else:
                            print(f"[{get_current_time()}]: {red_text('[ACK NOT RECEIVED]')}")
                    else:
                        print(f"[{get_current_time()}]: {red_text('[MAC VERIFICATION FAILED]')}")
                else:
                    print(f"[{get_current_time()}]: {red_text('[MAC VERIFICATION FAILED]')}")
            else:
                print(f"[{get_current_time()}]: {red_text('[CERTIFICATE IS NOT VALID]')}")

def server_start():
    handle_client(SERVER=socket.socket(socket.AF_INET, socket.SOCK_STREAM))


if __name__ == "__main__":

    # check if user1 has public and private keys. Since public and private keys are generated simultaneously,
    # It is OK to just check one of them.
    if crypto.get_public_key(db.USER1_NAME) is None:
        crypto.generate_pb_pr_keys(db.USER1_NAME)

    # check if user1 has certification.
    if crypto.get_certificate(author_name=db.USER1_NAME) is None:
        get_certification_from_server()

    server_start()
