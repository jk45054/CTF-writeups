import socket
from binascii import unhexlify, hexlify
from struct import pack, unpack

HOST = "0.0.0.0"
PORT = 31337

def swap_endianness(data):
    return b''.join(data[i:i + 4][::-1] for i in range(0, len(data), 4))

def convert(data, key=[0x13, 0x37]):
    res = b''
    for i in range(len(data)):
        res += bytes([data[i] ^ key[i % len(key)]])
    return res

def decode(data):
    return swap_endianness(convert(data))

def encode(data):
    return convert(swap_endianness(data))



server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(5)
K = bytes.fromhex("7ed85751e7131b5eaf5592718bef79a9")
print(f"Client priv key K = {K.hex()}")
print(f"- bswapped priv key K = {swap_endianness(K).hex()}")

try:
    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Conn from {client_address}")
        c_x_raw = client_socket.recv(0x30)
        c_x = decode(c_x_raw)
        c_y_raw = client_socket.recv(0x30)
        c_y = decode(c_y_raw)
        print(f"recv c_x_raw: {c_x_raw.hex()}")
        print(f"recv c_x    : {c_x.hex()}")
        print(f"recv c_y_raw: {c_y_raw.hex()}")
        print(f"recv c_y    : {c_y.hex()}")

        s_x = encode(bytes.fromhex('9ff8e5b33498d404102131de64f005aebe0b3f9b4f308729462fecc4f136f0d67c8097a80b3e694ec89acdb5065f00a8'))
        print(f"Sending s_x: {s_x.hex()}")
        client_socket.sendall(s_x)

        s_y = encode(bytes.fromhex('984d94857418693901cd1613b79c9209ca0caf068237af1e6b28c51979e921dc579003216447303ebd69195eeb67b6bc'))
        print(f"Sending s_y: {s_y.hex()}")
        client_socket.sendall(s_y)

        s_verify = bytes.fromhex('f272d54c31860f')
        print(f"Sending s_verify: {s_verify.hex()}")
        client_socket.sendall(s_verify)

        c_verify = decode(client_socket.recv(0x7))
        print(f"Got c_verify: {c_verify.hex()}")

        client_socket.close()
except KeyboardInterrupt:
        print("shutdown")
finally:
    server_socket.close()



