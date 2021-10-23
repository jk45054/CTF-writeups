import socketserver

class MyTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        # A Request to ipapi.com was made in wizardcult.pcap at Packet Number 437
        # GET /json/ HTTP/1.1
        # Host: ip-api.com
        self.data = self.request.recv(1024).strip()
        print("{} wrote:".format(self.client_address[0]))
        print(self.data)

        # The Answer was recorded as Packet Number 439
        # Just sent the same Message back to every Request
        ipapimsg = b"""{"status":"success","country":"United States","countryCode":"US","region":"XX","regionName":"Xxxxxxxx","city":"xxxxxx","zip":"xxxxx","lat":00.0000,"lon":-00.0000,"timezone":"America/New_York","isp":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx","org":"xxxxxxxxxxxxxxxxxxxxxx","as":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx","query":"00.00.000.000"}"""
        print(f"[*] sending back: {ipapimsg}")
        self.request.sendall(ipapimsg)

if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 80
    with socketserver.TCPServer((HOST, PORT), MyTCPHandler) as server:
        server.serve_forever()
