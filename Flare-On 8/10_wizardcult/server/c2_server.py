import socketserver

class MyTCPHandler(socketserver.StreamRequestHandler):
      global IRC_LOG
      
      def sendout(self, msg):
            # print out reply to console
            print(msg.strip())

            # convert to bytes and write reply msg to socket
            self.wfile.write(msg.encode())
            self.wfile.flush()

      def handle(self):
            # dungeon/potion index
            self.dungeon_index = 1

            while True:
                  # read next line from connection
                  self.data = self.rfile.readline().strip()
                  if len(self.data) == 0:
                        print("FATAL: Connection lost")
                        self.dungeon_index = 1
                        break
                        
                  # print out received line to console
                  print(self.data.decode())
                  
                  # very first induct message should begin with CAP LS 302 -> make sure to also get NICK message to parse for the randomly chosen nickname
                  if self.data.startswith(b"CAP LS"):
                        # sometimes the GIRC module sends out "CAP LS 302" on its own line, sometimes together with "NICK" and other times even together with "USER"
                        # parse request for (randomized) IRC username
                        if b"NICK" in self.data:
                              self.nick = self.data.split(b"\r\n")[1]
                              self.nick = bytes.decode(self.nick).split(" ")[1].strip()
                        if b"NICK" not in self.data:
                              # seems like "CAP LS 302" came in on a line by itself
                              # we need to fetch one more line to receive the randomly picked NICK
                              self.data = self.rfile.readline().strip()
                              # print out received line to console
                              print(self.data.decode())
                              self.nick = bytes.decode(self.data).split(" ")[1].strip()
                        # initialize reply strings and replace Izahl (from recorded IRC traffic in pcap) with received username
                        self.notice_hostname = IRC_LOG[2]
                        # server info in lines 5-31
                        self.server_info = "".join(IRC_LOG[4:31]).replace("Izahl", self.nick)
                        # channel info for #dungeon in lines 33-35
                        self.channel_info = "".join(IRC_LOG[32:35]).replace("Izahl", self.nick)
                        # who and mode info for #dungeon in lines 38-43
                        self.who_and_mode_info = "".join(IRC_LOG[37:43]).replace("Izahl", self.nick)
                        # ask for quest
                        self.ask_for_quest = IRC_LOG[44].replace("Izahl", self.nick)
                        # welcome to the party
                        self.welcome_to_party = IRC_LOG[46].replace("Izahl", self.nick)
                        # first potion recipe (encoded custom vm config)
                        self.recipe_acid_resistance = "".join(IRC_LOG[47:72]).replace("Izahl", self.nick)
                        # first dungeon description (encoded c2 command) -> ls /mages_tower
                        self.dungeon_grafs_infernal_disco = IRC_LOG[73].replace("Izahl", self.nick)
                        # first encounter message (goblin)
                        self.encounter_goblin = IRC_LOG[75].replace("Izahl", self.nick)
                        # second potion recipe (encoded custom vm config)
                        self.recipe_water_breathing = "".join(IRC_LOG[88:150]).replace("Izahl", self.nick)
                        # second dungeon description (encoded c2 command) -> /mages_tower/cool_wizard_meme.png
                        self.dungeon_sunken_crypt = "".join(IRC_LOG[151:153]).replace("Izahl", self.nick)
                        # second encounter message (wyvern)
                        self.encounter_wyvern = IRC_LOG[154].replace("Izahl", self.nick)
                        # start off IRC server mock up with first messages after receiving CAP LS, NICK and (mayhaps) USER messages
                        self.sendout(self.notice_hostname)
                        self.sendout(self.server_info)

                  # got JOIN #dungeon, send back channel info
                  elif self.data.startswith(b"JOIN"):
                        self.sendout(self.channel_info)
                  # got MODE, send back WHO and MODE info for #dungeon
                  elif self.data.startswith(b"MODE"):
                        self.sendout(self.who_and_mode_info)
                  # got first PRIVMSG with name, level, class (encoded OS) and land (encoded IPv4-Address), ask for quest
                  elif self.data.startswith(b"PRIVMSG #dungeon :Hello, I am"):
                        self.sendout(self.ask_for_quest)
                  # got quest, send back welcome to party and first potion recipe (custom vm config) / Potion of Acid Resistance
                  elif self.data.startswith(b"PRIVMSG #dungeon :My quest is"):
                        self.sendout(self.welcome_to_party)
                        self.sendout(self.recipe_acid_resistance)
                  # got potion recipe confirmation, send back c2 command for current dungeon_index
                  elif self.data.startswith(b"PRIVMSG #dungeon :I have now learned"):
                        if self.dungeon_index == 1:        
                              self.sendout(self.dungeon_grafs_infernal_disco)
                        elif self.dungeon_index == 2:
                              self.sendout(self.dungeon_sunken_crypt)
                  # got "I draw my sword", send back encounter message for current dungeon_index
                  elif self.data.startswith(b"PRIVMSG #dungeon :I draw my sword"):
                        if self.dungeon_index == 1:
                              self.sendout(self.encounter_goblin)
                        elif self.dungeon_index == 2:
                              self.sendout(self.encounter_wyvern)
                  # got "I do believe" at end of spellcasting (encoded exfiltrated data for c2 command execution) -> increase dungeon_index
                  elif self.data.startswith(b"PRIVMSG #dungeon :I do believe"):
                        if self.dungeon_index == 1:
                              self.dungeon_index += 1
                              self.sendout(self.recipe_water_breathing)
                  # receive PING message from a GIRC thread -> reply PONG (see RFC 2812)
                  elif self.data.startswith(b"PING"):
                        self.ping_value = self.data.decode().split(" ")[1].strip()
                        self.sendout(f":irc.local PONG {self.ping_value}\r\n")
                  else:
                        pass

if __name__ == "__main__":
      HOST, PORT = "0.0.0.0", 6667
      
      with open("../IRC-dump/irc_chat_full.txt", "r") as f:
            IRC_LOG = f.readlines()

      with socketserver.TCPServer((HOST, PORT), MyTCPHandler) as server:
            server.serve_forever()
