from dataclasses import dataclass
import socket
import time


@dataclass
class ConnectionConfigs:
    BUFF_SIZE = 2048  # set the chunk size
    PORT = 3000  # set port for server
    SERVER = socket.gethostbyname(socket.gethostname())  # get hos ip
    ADDR = (SERVER, PORT)  # fully address tupple
    FORMAT = 'utf-8'  # encode/decode format
    USER1_PORT = 3003
    USER2_PORT = 3004
    USER1_ADDR = (SERVER, USER1_PORT)
    USER2_ADDR = (SERVER, USER2_PORT)


@dataclass
class DatabaseConfigs:
    SERVER_NAME = "server"
    USER1_NAME = "user1"
    USER2_NAME = "user2"
    SERVER_DB_PATH = "server_database/"
    USER1_DB_PATH = "user1_database/"
    USER2_DB_PATH = "user2_database/"


def get_current_time():
    return time.strftime("%H:%M:%S:%M", time.localtime())

def yellow_text(text):
    return f"\033[93m{text}\033[0m"

def green_text(text):
    return f"\033[92m{text}\033[0m"

def red_text(text):
    return f"\033[91m{text}\033[0m"

def blue_text(text):
    return f"\033[94m{text}\033[0m"

def purple_text(text):
    return f"\033[95m{text}\033[0m"
