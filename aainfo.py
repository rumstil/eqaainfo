#
# Script for reading network stream from PCAP recording and attempting to parse
# Everquest AA data
# Currently works with Test Server as of 9/11/2018
#
import io
import re
import sys
import datetime
from lib import eqreader

AATableOpcode = 0x2348

OutputFile = 'aainfo.txt'
DBStringsFile = 'data/dbstr_us.txt'
DBSpellsFile = 'data/spells_us.txt'


# Slot count + Slot 1/SPA info used to search for the AATableOpcode if it is
# unknown
# Everyone has these and rank 1 seems to show up after a /resetAA
WellKnownAAList = [[1, 0, 0, 0, 107, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0], # Battle Ready 1
  [1, 0, 0, 0, 107, 1, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0], # Battle Ready 2
  [1, 0, 0, 0, 107, 1, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0], # Battle Ready 3
  [1, 0, 0, 0, 107, 1, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0], # Battle Ready 4
  [16, 0, 0, 0, 83, 1, 0, 0, 40, 0, 0, 0, 36, 147, 0, 0, 1, 0, 0, 0], # Banestrike 1
  [1, 0, 0, 0, 221, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0], # Packrat 1
  [1, 0, 0, 0, 221, 0, 0, 0, 33, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0], # Packrat 11
  [1, 0, 0, 0, 246, 0, 0, 0, 110, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0] # Innate Lung Capacity 1
]

AAData = dict()
DBDescStrings = dict()
DBTitleStrings = dict()
DBSpells = dict()


# Pulls all Titles from EQ DB files.
# DB Srtings Example: 16366^1^Sorcerer's Vengeance^0^
def loadDBStrings():
    try:
        print('Loading Strings DB from %s' % DBStringsFile, file=sys.stderr)
        db = open(DBStringsFile, 'r')
        for line in db:
            result = re.match(r'^(\d+)\^(\d)\^([\w\s\'\-\(\)\:\+\.\,\"\/\%\#\<\>]+?)\^[0]\^$', line)
            if (result != None and result.group(2) == '1'):
                DBTitleStrings[int(result.group(1))] = result.group(3)
            elif (result != None and result.group(2) == '4'):
                DBDescStrings[int(result.group(1))] = result.group(3)

        if (len(DBTitleStrings) > 0):
            print('Found %d titles' % len(DBTitleStrings))
        else:
            print('No titles found, copy over latest from your EQ directory?', file=sys.stderr)
        if (len(DBDescStrings) > 0):
            print('Found %d descriptions' % len(DBDescStrings), file=sys.stderr)
        else:
            print('No descriptions found, copy over latest from your EQ directory?', file=sys.stderr)
    except Exception as error:
        print(error)

# Spells US Example: 2754^Frenzied Burnout I^
def loadDBSpells():
    try:
        print('Loading Spells DB from %s' % DBSpellsFile, file=sys.stderr)
        db = open(DBSpellsFile, 'r')
        for line in db:
            result = re.match(r'^(\d+)\^([\w\s\'\-\(\)\:\+]+?)\^', line)
            if (result != None):
                DBSpells[int(result.group(1))] = result.group(2)
        if (len(DBSpells) > 0):
            print('Found %d entries' % len(DBSpells))
        else:
            print('No data found, copy over latest from your EQ directory?', file=sys.stderr)
    except Exception as error:
        print(error)

def findOpcode(opcode, buffer):
    global AATableOpcode

    # eliminate packets obviously too small for an AA
    size = len(buffer)
    if (size >= 100):
        found = False
        for aa in WellKnownAAList:
            start = 0
            end = len(aa)
            while (not found and end <= size):
                if (buffer[start:end] == aa):
                    AATableOpcode = opcode
                    found = True
                else:
                    start += 1
                    end += 1

def readBytes(buffer, count):
    value = buffer[0:count]
    del buffer[0:count]
    return value

def readInt32(buffer):
    value = buffer[0:4]
    del buffer[0:4]
    return int.from_bytes(value, 'little', signed=True)

def readUInt16(buffer):
    value = buffer[0:2]
    del buffer[0:2]
    return int.from_bytes(value, 'little', signed=False)

def readUInt32(buffer):
    value = buffer[0:4]
    del buffer[0:4]
    return int.from_bytes(value, 'little', signed=False)

def handleEQPacket(opcode, size, bytes, pos, time):
    global AAData

    # handle search for opcode
    if (AATableOpcode == 0):
        findOpcode(opcode, list(bytes[pos:]))

    # save an AA if the opcode is correct
    elif (AATableOpcode != 0 and opcode == AATableOpcode):
        try:
            buffer = list(bytes[pos:pos + size])
            descID = readInt32(buffer)
            readBytes(buffer, 1) # always 1
            hotKeySID = readInt32(buffer)
            hotKeySID2 = readInt32(buffer)
            titleSID = readInt32(buffer)
            descSID2 = readInt32(buffer)
            reqLevel = readUInt32(buffer)
            cost = readUInt32(buffer)
            aaID = readUInt32(buffer)
            rank = readUInt32(buffer)

            reqSkills = []
            reqSkillCount = readUInt32(buffer)
            if (reqSkillCount < 5): # or some reasonable value so theres no crazy long loops
                for _ in range(reqSkillCount):
                    value = readUInt32(buffer)
                    if (value > 0):
                        reqSkills.insert(0, value)
            else:
                raise TypeError('handleEQPacket: Bad AA format')

            reqRanks = []
            reqRankCount = readUInt32(buffer)
            if (reqRankCount < 5): # or some reasonable value so theres no crazy long loops
                for _ in range(reqRankCount):
                    value = readUInt32(buffer)
                    if (value > 0):
                        reqRanks.insert(0, value)
            else:
                raise TypeError('handleEQPacket: Bad AA format')

            type = readUInt32(buffer)
            spellID = readInt32(buffer)
            readUInt32(buffer) # always 1
            abilityTimer = readUInt32(buffer)
            refreshTime = readUInt32(buffer)
            #classMask = readUInt16(buffer)
            #berserkerMask = readUInt16(buffer)
            classMask = readUInt32(buffer) >> 1
            maxRank = readUInt32(buffer)
            prevDescSID = readInt32(buffer)
            nextDescSID = readInt32(buffer)
            totalCost = readUInt32(buffer)
            readBytes(buffer, 10) # unknown
            expansion = readUInt32(buffer)
            category = readInt32(buffer)
            readBytes(buffer, 4) #unknown
            expansion2 = readUInt32(buffer) # required expansion?  it's not always set
            maxActivationLevel = readUInt32(buffer) # max player level that can use the AA
            isGlyph = readBytes(buffer, 1)
            spaCount = readUInt32(buffer)
            spaData = []
            for _ in range(spaCount):
                #spa = readUInt32(buffer)
                #base1 = readInt32(buffer)
                #base2 = readInt32(buffer)
                #slot = readUInt32(buffer)
                for _ in range(4):
                    spaData.append(readInt32(buffer))


            # output the spell in eqspellparser aa format
            data = []
            data.append(descID)
            data.append(aaID)
            data.append(prevDescSID)
            data.append(titleSID)
            data.append(descSID2)
            data.append(rank)
            data.append(maxRank)
            data.append(classMask)
            data.append(reqLevel)
            data.append(cost)
            data.append(totalCost)
            data.append(spellID)
            data.append(refreshTime)
            data.append(abilityTimer)
            data.append(type)
            data.append(expansion)
            data.append(category)
            data.append(','.join([str(x) for x in spaData]))
            if reqSkills:
                data.append(','.join([str(x) + ',' + str(y) for x, y in zip(reqSkills, reqRanks)]))
            else:
                data.append('0,0') # just to match what the eqextractor dump was
            data.append(datetime.datetime.fromtimestamp(time).isoformat()[0:10])
            

            print('^'.join([str(x) for x in data]))

            AAData[aaID] = data

        except TypeError as error:
            print(error, file=sys.stderr)
            pass #print(error)

def main(args):
    global AATableOpcode, AAData

    if (len(args) < 2):
        print('Usage: ' + args[0] + ' <pcap file>', file=sys.stderr)
        return

    #loadDBStrings()
    #loadDBSpells()

    try:
        print('Reading %s' % args[1], file=sys.stderr)
        eqreader.readPcap(handleEQPacket, args[1])
        if (len(AAData) == 0):
            print('No AAs found using opcode: %s, searching for updated opcode' % hex(AATableOpcode), file=sys.stderr)
            AATableOpcode = 0
            eqreader.readPcap(handleEQPacket, args[1])
            if (AATableOpcode > 0):
                print('Found likely opcode: %s, trying to parse AA data again' % hex(AATableOpcode), file=sys.stderr)
                AAData = dict()
                eqreader.readPcap(handleEQPacket, args[1])
                if (len(AAData) == 0):
                    print('AA Format has most likely changed and can not be parsed', file=sys.stderr)
            else:
                print('Could not find opcode, giving up', file=sys.stderr)
    except Exception as error:
        print(error, file=sys.stderr)

main(sys.argv)
