import socket
from configs import ConnectionConfigs as conn
from configs import DatabaseConfigs as db
from configs import get_current_time
import crypto
import json
import time


def create_certificate(user_pub_key):
    user_certificate = crypto.create_digital_signature(message=user_pub_key, private_key_author=db.SERVER_NAME)
    return user_certificate


def server_listen(SERVER):
    while True:
        print(
            f"[{get_current_time()}]: {'*'*10} Cilent Session Started {'*'*10}")
        socket, address = SERVER.accept()  # accept client
        print(f"[{get_current_time()}]: --> [CONNECTION ACCCEPTED -> {address}]")

        message = socket.recv(conn.BUFF_SIZE)
        msg_in_str = message.decode(conn.FORMAT)
        msg_dict = json.loads(msg_in_str)
        username = msg_dict['username']
        user_pub_key = msg_dict['pub_key'].encode(conn.FORMAT)

        user_certificate = create_certificate(user_pub_key=user_pub_key)
        crypto.save_certificate(certificate=user_certificate, author_name=username)
        print(f"[{get_current_time()}]: [{username}'s CERTIFICATE {user_certificate} CREATED AND SENDING]")
        socket.send(user_certificate)

        socket.close()
        print(f"[{get_current_time()}]: --> [CONNECTION CLOSING -> {address}]")
        print(
            f"[{get_current_time()}]: {'*'*10} Cilent Session Ends {'*'*10}\n")


def server_start():
    # check if server has public and private keys. Since public and private keys are generated simultaneously,
    # It is OK to just check one of them.
    if crypto.get_public_key(db.SERVER_NAME) is None:
        crypto.generate_pb_pr_keys(db.SERVER_NAME)

    SERVER = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    SERVER.bind(conn.ADDR)
    SERVER.listen()
    server_listen(SERVER=SERVER)


if __name__ == "__main__":
    server_start()
