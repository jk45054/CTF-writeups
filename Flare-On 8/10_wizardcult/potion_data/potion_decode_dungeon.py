import sys

descriptions = dict()
with open("dumped_dungdesctable.txt", "r") as f:
    for desc in f:
        index, name = desc.split('=')
        descriptions[name.rstrip()] = int(index, 16)
f.close()

dungeon = bytearray()
with open(sys.argv[1], "r") as f:
    dungeonDesc = f.readline()
f.close()

descList = dungeonDesc.split(", ")
for i in descList:
    dungeon.append(descriptions[i])
print(dungeon.decode("ascii"))
