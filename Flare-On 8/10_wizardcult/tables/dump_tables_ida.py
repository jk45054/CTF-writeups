# 942EA0 wizardcult_tables_DungeonDescriptions dq offset DungeonDescTable_94FB00
# 942EA8 dqNumDescriptions dq 2E8h

# 942EC0 wizardcult_tables_Ingredients dq offset IngredientsTable_94B580
# 942EC8 dqNumIngredients dq 100h

# 942EE0 wizardcult_tables_Names dq offset NamesTable_948DC0
# 942EE8 dqNumNames      dq 28h

# 942F00 wizardcult_tables_Places dq offset PlacesTable_94C580
# 942F08 dqNumPlaces     dq 100h

# 942F20 wizardcult_tables_Spells dq offset SpellTable_94E5A0
# 942F28 dqNumSpells     dq 155h

for (name, start, numEntries) in (("Dungeon Descriptions", 0x94FB00, 0x2E8), ("Ingredients", 0x94B580, 0x100), ("Names", 0x948DC0, 0x28), ("Places", 0x94C580, 0x100), ("Spells", 0x94E5A0, 0x155)):
    print("-"*50)
    print(f"Dumping Table {name} with offset {hex(start)}, size {hex(numEntries)}")
    print
    index = 0
    while (index < numEntries):
        ea = start + index * 16
        pEntry = int.from_bytes(get_bytes(ea, 8), sys.byteorder)
        dqEntryLen = int.from_bytes(get_bytes(ea + 8, 8), sys.byteorder)
        Entry = get_bytes(pEntry, dqEntryLen).decode("ascii")
        print(f"{hex(index)}={Entry}")
        index += 1