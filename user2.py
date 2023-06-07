import base64
import socket
from configs import ConnectionConfigs as conn
from configs import DatabaseConfigs as db
from configs import get_current_time
from configs import yellow_text, green_text, red_text, blue_text, purple_text
import crypto
import json
from colorama import Fore, Back, Style

user2_public_key = None
user2_private_key = None
user2_certificate = None
user1_public_key = None


def get_certification_from_server():
    SERVER = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    SERVER.connect(conn.ADDR)

    global user2_public_key
    user2_public_key = crypto.get_public_key(public_key_author=db.USER2_NAME)

    global user2_private_key
    user2_private_key = crypto.get_private_key(private_key_author=db.USER2_NAME)

    global user1_public_key
    user1_public_key = crypto.get_public_key(public_key_author=db.USER1_NAME)

    pub_key = user2_public_key.save_pkcs1()
    msg = {"username": db.USER2_NAME,
           "pub_key": pub_key.decode(conn.FORMAT)}

    msg = json.dumps(msg).encode(conn.FORMAT)
    SERVER.send(msg)

    certificate = SERVER.recv(conn.BUFF_SIZE)

    global user2_certificate
    user2_certificate = crypto.get_certificate(author_name=db.USER2_NAME)

    if crypto.verify_digital_signature(message=pub_key, signature=certificate, author_name=db.SERVER_NAME):
        print(f"[{get_current_time()}]: [CERTIFICATE IS CORRECT] -> saving...")
        crypto.save_certificate(certificate=certificate, author_name=db.USER2_NAME)
    else:
        print(f"[{get_current_time()}]: Error: Certification got error")


def create_message_with_certificate(message, symmetric_key):
    message = json.dumps(
        {"message": message, "certificate": base64.b64encode(user2_certificate).decode(conn.FORMAT)}).encode(
        conn.FORMAT)
    print(f"[{get_current_time()}]: [CREATED MESSAGE WITH CERTIFICATE]")
    mac = crypto.generate_mac(message, symmetric_key)
    print(f"[{get_current_time()}]: [GENERATED MAC (HMAC)]")
    mac = crypto.create_digital_signature(mac, db.USER2_NAME)
    print(f"[{get_current_time()}]: [APPLIED DIGITAL SIGNATURE ON MAC (RSA)]")

    content_of_ks = json.dumps(
        {"message": message.decode(conn.FORMAT), "mac": base64.b64encode(mac).decode(conn.FORMAT)}).encode(conn.FORMAT)
    # encrypt message with symmetric key
    iv, ciphertext = crypto.aes_cbc_encryption(content_of_ks, symmetric_key)
    print(f"[{get_current_time()}]: [ENCRYPTED MESSAGE WITH SYMMETRIC KEY (AES-CBC)]")

    msg_dict = {"iv": base64.b64encode(iv).decode(conn.FORMAT),
                "ciphertext": base64.b64encode(ciphertext).decode(conn.FORMAT)}
    return json.dumps(msg_dict).encode(conn.FORMAT)


def create_message(message, symmetric_key):
    message = json.dumps({"message": message}).encode(conn.FORMAT)
    print(f"[{get_current_time()}]: [CREATED MESSAGE]")

    mac = crypto.generate_mac(message, symmetric_key)
    print(f"[{get_current_time()}]: [GENERATED MAC (HMAC)]")
    mac = crypto.create_digital_signature(mac, db.USER2_NAME)
    print(f"[{get_current_time()}]: [APPLIED DIGITAL SIGNATURE ON MAC (RSA)]")

    content_of_ks = json.dumps(
        {"message": message.decode(conn.FORMAT), "mac": base64.b64encode(mac).decode(conn.FORMAT)}).encode(conn.FORMAT)
    # encrypt message with symmetric key
    iv, ciphertext = crypto.aes_cbc_encryption(content_of_ks, symmetric_key)
    print(f"[{get_current_time()}]: [ENCRYPTED MESSAGE WITH SYMMETRIC KEY (AES-CBC)]")

    msg_dict = {"iv": base64.b64encode(iv).decode(conn.FORMAT),
                "ciphertext": base64.b64encode(ciphertext).decode(conn.FORMAT)}
    return json.dumps(msg_dict).encode(conn.FORMAT)


def receive_message_with_certificate(msg, symmetric_key=None):
    msg_in_str = msg.decode(conn.FORMAT)
    msg_dict = json.loads(msg_in_str)
    iv = base64.b64decode(msg_dict['iv'].encode(conn.FORMAT))
    ciphertext = base64.b64decode(msg_dict['ciphertext'].encode(conn.FORMAT))
    # if there is no symmetric key section in message, skip
    encrypted_ks = None
    try:
        encrypted_ks = base64.b64decode(msg_dict['encrypted_ks'].encode(conn.FORMAT))
    except KeyError:
        print("No encrypted_ks in message")
        pass

    # decrypt encrypted_ks
    if symmetric_key is None:
        symmetric_key = crypto.decrypt_with_rsa_private(encrypted_ks, user2_private_key)
        print(f"[{get_current_time()}]: [OBTAINED SYMMETRIC KEY]")

    # decrypt ciphertext
    content_of_ks = crypto.aes_cbc_decryption(iv, ciphertext, symmetric_key)
    print(f"[{get_current_time()}]: [DECRYPTED MESSAGE WITH SYMMETRIC KEY (AES-CBC)]")
    content_of_ks = content_of_ks.decode(conn.FORMAT)
    content_of_ks = json.loads(content_of_ks)

    content_of_mac = content_of_ks['message'].encode(conn.FORMAT)
    mac = base64.b64decode(content_of_ks['mac'].encode(conn.FORMAT))
    calculated_mac = crypto.generate_mac(content_of_mac, symmetric_key)
    mac_verification = crypto.verify_digital_signature(message=calculated_mac, signature=mac, author_name=db.USER1_NAME)
    print(f"[{get_current_time()}]: {green_text('[VERIFIED MAC (HMAC)]')}")

    return [json.loads(content_of_mac.decode(conn.FORMAT))['message'], base64.b64decode(
        json.loads(content_of_mac.decode(conn.FORMAT))['certificate'].encode(conn.FORMAT)), mac_verification,
            symmetric_key]


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
    mac_verification = crypto.verify_digital_signature(message=calculated_mac, signature=mac, author_name=db.USER1_NAME)
    print(f"[{get_current_time()}]: {green_text('[VERIFIED MAC (HMAC)]')}")

    return [json.loads(content_of_mac.decode(conn.FORMAT))['message'], mac_verification]


def handle_client(SERVER):
    print(
        f"[{get_current_time()}]: {'*' * 10} Cilent Session Started {'*' * 10}")
    while True:
        socket, address = SERVER.accept()

        global user2_private_key
        user2_private_key = crypto.get_private_key(private_key_author=db.USER2_NAME)
        global user2_public_key
        user2_public_key = crypto.get_public_key(public_key_author=db.USER2_NAME)
        global user1_public_key
        user1_public_key = crypto.get_public_key(public_key_author=db.USER1_NAME)
        global user2_certificate
        user2_certificate = crypto.get_certificate(author_name=db.USER2_NAME)

        msg = socket.recv(conn.BUFF_SIZE).decode(conn.FORMAT)
        print(f"[{get_current_time()}]: {yellow_text('<-- [RECEIVED MESSAGE FROM ' + str(address) + ']: ' + msg)}")

        if msg == "SYN":
            # send syn-ack to user1 server
            socket.send("SYN-ACK".encode(conn.FORMAT))
            print(f"[{get_current_time()}]: {yellow_text('--> [SYN-ACK SENT TO ' + str(address) + ']')}")

            # wait for ack from user1 server
            msg = socket.recv(conn.BUFF_SIZE).decode(conn.FORMAT)
            print(f"[{get_current_time()}]: {yellow_text('<-- [RECEIVED MESSAGE FROM ' + str(address) + ']: ' + msg)}")

            # wait for message from user1 server
            msg = socket.recv(conn.BUFF_SIZE)
            print(f"[{get_current_time()}]: {yellow_text('<-- [RECEIVED MESSAGE FROM ' + str(address) + ']: ' + str(msg))}")

            message_content = receive_message_with_certificate(msg)
            message = message_content[0]
            certificate = message_content[1]
            mac_verification = message_content[2]
            symmetric_key = message_content[3]

            # verify mac
            if crypto.verify_digital_signature(message=user1_public_key.save_pkcs1(), signature=certificate,
                                               author_name=db.SERVER_NAME):
                print(f"[{get_current_time()}]: {green_text('[CERTIFICATION IS VALID]')}")
                if mac_verification:
                    print(f"[{get_current_time()}]: {blue_text('[MESSAGE]: ' + message)}")
                    nonce = crypto.generate_nonce()
                    msg = create_message_with_certificate(base64.b64encode(nonce).decode(conn.FORMAT), symmetric_key)
                    socket.send(msg)
                    print(f"[{get_current_time()}]: {yellow_text('--> [NONCE AND CERTIFICATE SENT TO ' + str(address) + ']')}")

                    msg = socket.recv(conn.BUFF_SIZE)
                    print(f"[{get_current_time()}]: {yellow_text('<-- [RECEIVED MESSAGE FROM ' + str(address) + ']: ' + str(msg))}")

                    message_content = receive_message(msg, symmetric_key)
                    message = message_content[0]
                    mac_verification = message_content[1]

                    if mac_verification:
                        if crypto.verify_digital_signature(message=nonce,
                                                           signature=base64.b64decode(message.encode(conn.FORMAT)),
                                                           author_name=db.USER1_NAME):
                            print(f"[{get_current_time()}]: {green_text('[NONCE IS VERIFIED]')}")
                            # send ack to user1 server
                            msg = create_message_with_certificate("ACK", symmetric_key)
                            socket.send(msg)
                            print(f"[{get_current_time()}]: {yellow_text('--> [ACK SENT TO ' + str(address) + ']')}")
                            print(f"[{get_current_time()}]: {green_text('[SESSION ESTABLISHED]')}")
                            print(f"[{get_current_time()}]: {green_text('[STARTING CHAT]')}")

                            while True:
                                # wait for message from user1 server
                                print(f"[{get_current_time()}]: {blue_text('[WAITING FOR MESSAGE]')}")
                                msg = socket.recv(conn.BUFF_SIZE)
                                print(f"[{get_current_time()}]: {yellow_text('<-- [RECEIVED MESSAGE FROM ' + str(address) + ']: ' + str(msg))}")
                                message_content = receive_message(msg, symmetric_key)
                                message = message_content[0]
                                mac_verification = message_content[1]

                                if mac_verification:
                                    print(f"[{get_current_time()}]: {blue_text('[MESSAGE FROM ' + str(conn.USER1_ADDR) + ']: ' + purple_text(message))}")
                                    # get input from user and send it to user2 server
                                    msg = input(f"[{get_current_time()}]: {blue_text('[YOU]: ')}")
                                    socket.send(create_message(msg, symmetric_key))
                                    print(f"[{get_current_time()}]: {yellow_text('--> [MESSAGE SENT TO ' + str(conn.USER1_ADDR) + ']')}")
                                else:
                                    print(f"[{get_current_time()}]: [MAC VERIFICATION FAILED]")
                        else:
                            print(f"[{get_current_time()}]: [NONCE VERIFICATION FAILED]")
                    else:
                        print(f"[{get_current_time()}]: [MAC VERIFICATION FAILED]")
                else:
                    print(f"[{get_current_time()}]: [MAC VERIFICATION FAILED]")
            else:
                print(f"[{get_current_time()}]: [CERTIFICATE IS NOT VALID]")


def server_start():
    SERVER = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    SERVER.bind(conn.USER2_ADDR)
    SERVER.listen()
    handle_client(SERVER=SERVER)


if __name__ == "__main__":
    # check if user1 has public and private keys. Since public and private keys are generated simultaneously,
    # It is OK to just check one of them.
    if crypto.get_public_key(db.USER2_NAME) is None:
        crypto.generate_pb_pr_keys(db.USER2_NAME)

    # check if user2 has certification.
    if crypto.get_certificate(author_name=db.USER2_NAME) is None:
        get_certification_from_server()

    server_start()
