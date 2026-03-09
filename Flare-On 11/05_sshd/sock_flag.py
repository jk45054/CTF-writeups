import socket
from binascii import unhexlify
from struct import pack, unpack

key = unhexlify("8dec9112eb760eda7c7d87a443271c35d9e0cb878993b4d904aef934fa2166d7")
nonce = unhexlify("111111111111111111111111")
filename = "/tmp/enc.bin"

HOST = "0.0.0.0"
PORT = 1337

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(5)

try:
    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Conn from {client_address}")

        # send 0x20 key bytes
        client_socket.sendall(key)
        # send 0xd nonce bytes
        client_socket.sendall(nonce)
        # send 4 bytes filename len
        file_len = pack("<I", len(filename))
        print(f"file len: {file_len}")
        client_socket.sendall(file_len)
        # send filename
        client_socket.sendall(filename.encode('utf-8'))
        # recv dec len
        dec_len = int.from_bytes(client_socket.recv(4), "little")
        print(f"dec len {dec_len}")
        dec_buf = client_socket.recv(dec_len)
        print(f"dec buf: {dec_buf}")
        # recv dec buf
        client_socket.close()
except KeyboardInterrupt:
        print("shutdown")
finally:
    server_socket.close()



