#
# Script for reading network stream from PCAP recording and attempting to parse Everquest AA data
#

import io
import re
import sys
from lib.util import *
from lib.eqdata import *
from lib.eqreader import *

AATableOpcode = 0x1142 # On Beta 11/20/18
OutputFile = 'aainfo.txt'

Categories = ['', '', 'Progression', '', '', 'Veteran Reward', 'Tradeskill', 'Expendable', 'Racial Innate', 'Everquest', '', 'Item Effect']
Types = ['Unknown', 'General', 'Archetype', 'Class', 'Special', 'Focus']

# Slot count + Slot 1/SPA info used to search for the AATableOpcode if it is unknown
# Everyone has these and rank 1 seems to show up after a /resetAA
WellKnownAAList = [
  bytearray([1, 0, 0, 0, 107, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]),     # Battle Ready 1
  bytearray([1, 0, 0, 0, 107, 1, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]),     # Battle Ready 2
  bytearray([1, 0, 0, 0, 107, 1, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]),     # Battle Ready 3
  bytearray([1, 0, 0, 0, 107, 1, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]),     # Battle Ready 4
  bytearray([16, 0, 0, 0, 83, 1, 0, 0, 40, 0, 0, 0, 36, 147, 0, 0, 1, 0, 0, 0]), # Banestrike 1
  bytearray([1, 0, 0, 0, 246, 0, 0, 0, 110, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]),   # Innate Lung Capacity 1
  bytearray([1, 0, 0, 0, 233, 0, 0, 0, 110, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]),   # Innate Metabolism 1
  bytearray([1, 0, 0, 0, 233, 0, 0, 0, 125, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]),   # Innate Metabolism 2
  bytearray([1, 0, 0, 0, 233, 0, 0, 0, 150, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]),   # Innate Metabolism 3
  bytearray([1, 0, 0, 0, 221, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]),     # Packrat 1
  bytearray([1, 0, 0, 0, 221, 0, 0, 0, 33, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0])     # Packrat 11
]

AAData = dict()
DBDescStrings = DBTitleStrings = DBSpells = None

def findAAOpcode(opcode, bytes):
  global AATableOpcode

  # eliminate packets obviously too small for an AA
  count = 0
  size = len(bytes)
  if (size >= 100):
    found = False
    for aa in WellKnownAAList:
      start = 0
      end = len(aa)
      while (not found and end <= size):
        if (bytes[start:end] == aa):
          count += 1
          AATableOpcode = opcode
          if (count > 1):
            found = True
        else:
          start += 1
          end += 1
 
def handleEQPacket(opcode, bytes):
  global AAData
 
  # handle search for opcode
  if (AATableOpcode == 0):
    findAAOpcode(opcode, bytes)

  # save an AA if the opcode is correct
  elif (AATableOpcode != 0 and opcode == AATableOpcode):
    try:
      descID = readInt32(bytes)
      readInt8(bytes) # always 1
      hotKeySID = readInt32(bytes)
      hotKeySID2 = readInt32(bytes)
      titleSID = readInt32(bytes)
      descSID2 = readInt32(bytes)
      reqLevel = readUInt32(bytes)
      cost = readUInt32(bytes)
      aaID = readUInt32(bytes)
      rank = readUInt32(bytes)

      reqSkills = []
      reqSkillCount = readUInt32(bytes)
      if (reqSkillCount < 5): # or some reasonable value so theres no crazy long loops
        for s in range(reqSkillCount):
          value = readUInt32(bytes)
          if (value > 0):
            reqSkills.insert(0, value)
      else:
        raise TypeError('handleEQPacket: Bad AA format')

      reqRanks = []
      reqRankCount = readUInt32(bytes)
      if (reqRankCount < 5): # or some reasonable value so theres no crazy long loops
        for p in range(reqRankCount):
          value = readUInt32(bytes)
          if (value > 0):
            reqRanks.insert(0, value)
      else:
        raise TypeError('handleEQPacket: Bad AA format')

      type = readUInt32(bytes)
      spellID = readInt32(bytes)
      readUInt32(bytes) # always 1
      abilityTimer = readUInt32(bytes)
      refreshTime = readUInt32(bytes)
      classMask = readUInt16(bytes)
      berserkerMask = readUInt16(bytes)
      maxRank = readUInt32(bytes)
      prevDescSID = readInt32(bytes)
      nextDescSID = readInt32(bytes)
      totalCost = readUInt32(bytes)
      readBytes(bytes, 10) # unknown
      expansion = readUInt32(bytes)
      category = readInt32(bytes)
      readBytes(bytes, 4) #unknown
      expansion2 = readUInt32(bytes) # required expansion? it's not always set
      maxActivationLevel = readUInt32(bytes) # max player level that can use the AA
      isGlyph = readInt8(bytes) == 1
      spaCount = readUInt32(bytes)

      # lookup Title from DB
      if (titleSID == -1):
        raise TypeError('handleEQPacket: Bad AA format, missing title')

      title = DBTitleStrings.get(titleSID) 
      if (title == None):
        title = str(titleSID)
        if (len(DBTitleStrings) > 0):
          print('AA Title not found in DB, possible problem parsing data (format change?)')

      output = io.StringIO()
      output.write('Ability:         %s (%d)\n' % (title, rank))
      output.write('Activation ID:   %d\n' % aaID)

      if (type > -1):
        output.write('Category:        %s\n' % Types[type])
      if (category > -1):
        output.write('Category2:       %s\n' % Categories[category])

      # using class mask util from items so the data has to be shifted
      classString = getClassString((classMask >> 1) + (32768 if berserkerMask else 0))
      output.write('Classes:         %s\n' % classString)

      if (expansion >= 0 and expansion < len(Expansions)):
        expansion = Expansions[expansion]
      output.write('Expansion:       %s\n' % expansion)

      if (maxActivationLevel > 0):
        output.write('Max Level:       %d\n' % maxActivationLevel)
      output.write('Min Level:       %d\n' % reqLevel)
      output.write('Rank:            %d / %d\n' % (rank, maxRank))
      output.write('Rank Cost:       %d AAs\n' % cost)

      if (refreshTime > 0):
        output.write('Reuse Time:      %ds\n' % refreshTime)
        output.write('Timer ID:        %d\n' % abilityTimer)
      else:
        output.write('Reuse Time:      Passive\n')

      if (spellID > 0):
        spellName = DBSpells.get(spellID)
        if (spellName == None and len(DBSpells) > 0):
          print('Spell Title not found in DB for %d, possible problem parsing data (format change?)' % spellID)
        if (spellName == None):
          spellName = spellID
        else:
          spellName = '%s #%d' % (spellName, spellID)
        output.write('Spell:           %s\n' % spellName)

      output.write('Total Cost:      %d AAs\n' % totalCost)

      for i in range(len(reqRanks)):
        output.write('Requirements:    Rank %d of AA/Skill: %d\n' % (reqRanks[i], reqSkills[i]))

      if (spaCount > 0):
        output.write('Found %d SPA Slots:\n' % spaCount)

      for t in range(spaCount):
        spa = readUInt32(bytes)
        base1 = readInt32(bytes)
        base2 = readInt32(bytes)
        slot = readUInt32(bytes)
        output.write('   Slot:   %3d   SPA:   %3d   Base1:   %6d   Base2:   %6d\n' % (slot, spa, base1, base2))

      desc = DBDescStrings.get(descSID2)
      if (desc == None):
        desc = descSID2 
      else:
        desc = '\n   ' + desc.replace('<br><br>', '\n   ').replace('<br>', '\n   ')
      output.write('Description:    %s\n' % desc)

      output.write('\n')
      AAData['%s-%02d' % (title, rank)] = output.getvalue()
      output.close()
    except TypeError as error:
      pass #print(error)

def saveAAData():
  file = open(OutputFile, 'w')
  for key in sorted(AAData.keys()):
    file.write(AAData[key])
  file.close()
  print('Saved data for %d AAs to %s' % (len(AAData), OutputFile))

def main(args):
  global DBDescStrings, DBTitleStrings, DBSpells, AATableOpcode, AAData

  if (len(args) < 2):
    print ('Usage: ' + args[0] + ' <pcap file>')
  else:
    try:
      DBDescStrings, DBTitleStrings = loadDBStrings()
      DBSpells = loadDBSpells()

      print('Reading %s' % args[1])
      readPcap(handleEQPacket, args[1])
      if (len(AAData) > 0):
        saveAAData()
      else:
        print('No AAs found using opcode: %s, searching for updated opcode' % hex(AATableOpcode))
        AATableOpcode = 0
        readPcap(handleEQPacket, args[1])
        if (AATableOpcode > 0):
          print('Found likely opcode: %s, trying to parse AA data again' % hex(AATableOpcode))
          AAData = dict()
          readPcap(handleEQPacket, args[1])
          if (len(AAData) > 0):
            saveAAData()
            print('Update the default opcode to speed up this process in the future')
          else:
            print('AA Format has most likely changed and can not be parsed')
        else:
            print('Could not find opcode, giving up')
    except Exception as error:
      print(error)

main(sys.argv)