# Flare-On 10, Challenge 3, mypassion
#
# Script to run the challenge executable with
# One correct solution argument, calculates
# System.wDay value on the fly
#

from datetime import datetime
from subprocess import run

path = "../challenge_files/mypassion.exe"
param = "07KxxR@brUc3E/1337pr.ost/21xxxxxxxxx/ pizza/AMu$E`0R.fAZe/YPXEKCZXYIGMNOXNMXPYCXGXN/ob5cUr3/fin/"

offset_wDay = 37
base_value = 0x1F
# get SystemTime.wDay value for today
wDay = int(datetime.now().strftime("%d"), 10)
todays_char = chr(base_value + wDay)
# calculate correct first char for third slash string _pizza
param_today = param[:offset_wDay] + todays_char + param[offset_wDay + 1 :]
print(
    f"wDay = {wDay}, todays_char = {todays_char} ({hex(base_value + wDay)}), param for today = {param_today}"
)

# running program with param
run([path, param])
