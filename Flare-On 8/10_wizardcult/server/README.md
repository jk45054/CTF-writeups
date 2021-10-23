# Python Server Scripts to Emulate IP-Geolookup and C2 Communication

ipapi-server.py -> mock server returning the JSON value from wizardcult.pcap packet number 439

c2_server.py -> mock server replaying the IRC traffic from wizardcult.pcap (replacing nickname Izahl with the one randomly chosen by induct)

Run both server scripts on a host that induct connects to (wizardcult.flare-on.com & ip-api.com) -> e.g. by adding the host's IP address to /etc/hosts
