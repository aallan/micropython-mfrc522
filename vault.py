import json
import gc
from utime import ticks_ms, ticks_diff
from mfrc522 import MFRC522
#from timer import timeit
"""
def timeit(name):
    def factory(method):
        return method
    return factory
"""

"""The number of banks available in the tag. Only one is active, and has its length stored in the lengths block"""
numBanks = 3
"""Default Mifare key which authenticates access to card sectors"""
key = b'\xff\xff\xff\xff\xff\xff'
"""Number of bytes per block"""
bytesPerBlock = 16
"""Number of total blocks in 1k Mifare Classic tag"""
numBlocks = 64
"""Number of data (non-auth) blocks"""
numDataBlocks = (numBlocks // 4) * 3 # Every fourth block is an auth block, not used for banking
"""Block 0 is manufacturer-protected, block 1 is lengthblock and block 2 kept for future"""
numReservedDataBlocks = 3
"""Remaining authorable blocks"""
safeBlocks = numDataBlocks - numReservedDataBlocks
"""Authorable blocks allocated to each bank"""
blocksPerBank = safeBlocks // numBanks

"""Reserved block for keeping the length of JSON banks"""
lengthsRealIndex = 1

def getRealIndex(safeIndex):
    safeIndex = safeIndex + numReservedDataBlocks  # offset to skip reserved editable blocks
    return ((safeIndex // 3) * 4) + (safeIndex % 3)  # calculate index, skipping auth blocks

class BankVault:
    def __init__(self, reader):
        #reader used to put a JSON byte array (up to 240 bytes) onto the 1k Mifare Classic tag
        self.rdr = reader
        #Buffer used for writing
        self.blockBuffer = bytearray(bytesPerBlock)
        # currently selected tag (avoid reauth)
        self.selectedTagUid = None

#    @timeit('isTagPresent')
    def isTagPresent(self):
        (stat, tag_type) = self.rdr.request(MFRC522.REQIDL)  # check if antenna idle
        return stat is MFRC522.OK

#    @timeit('separateTag')
    def separateTag(self):
        (stat, tagUid) = self.rdr.anticoll()
        if stat is not MFRC522.OK:
            return None
        else:
            return tagUid

#    @timeit('getPresentTag')
    def getPresentTag(self):
        if not(self.isTagPresent()):
            return None
        else:
            return self.separateTag()

#    @timeit('awaitPresence')
    def awaitPresence(self, waitms=None):
        tagUid = None
        if waitms is not None:
            started = ticks_ms()
        else:
            started = None
        while tagUid is None and (waitms is None or ticks_diff(ticks_ms(), started) < waitms):
            tagUid = self.getPresentTag()
        return tagUid

    def awaitAbsence(self):
        errThreshold = 2
        errCount = 0
        while errCount < errThreshold:
            (stat, tag_type) = self.rdr.request(MFRC522.REQIDL)  # check if antenna idle
            if stat is MFRC522.OK:
                errCount = 0
            else:
                errCount += 1
        return

    # reimplemented as blocking via await presence
#    @timeit('selectTag')
    def selectTag(self, tagUid):
        if self.selectedTagUid is not None:
            if self.selectedTagUid == tagUid: # already selected
                return True
            else:
                self.unselectTag()
        if self.rdr.select_tag(tagUid) is MFRC522.OK:
            self.selectedTagUid = tagUid
            return True
        else:
            raise AssertionError("Selection")

#    @timeit('unselectTag')
    def unselectTag(self):
        self.selectedTagUid = None
        self.rdr.halt_a()
        self.rdr.stop_crypto1()

#    @timeit('readBlock')
    def readBlock(self, realBlockIndex, into=None):
        if self.selectedTagUid is None: raise AssertionError("Not selected")
        # TODO CH is this repeated auth always necessary, or only once?
        if self.rdr.auth(MFRC522.AUTHENT1A, realBlockIndex, key, self.selectedTagUid) is not MFRC522.OK: raise AssertionError("Auth")
        # TODO CH, optimise MFRC522 to prevent allocation here (implement 'readinto' function)
        if into is None:
            into= bytearray(bytesPerBlock)
        self.rdr.read(realBlockIndex, into=into)
        return into

#    @timeit('writeBlock')
    def writeBlock(self, realBlockIndex, data):
        if self.selectedTagUid is None: raise AssertionError("Not selected")
        # TODO CH is this repeated auth always necessary, or only once?
        if self.rdr.auth(MFRC522.AUTHENT1A, realBlockIndex, key, self.selectedTagUid) is not MFRC522.OK: raise AssertionError("Auth")
        return self.rdr.write(realBlockIndex, data)

    def readLengthsBlock(self, into=None):
        return self.readBlock(lengthsRealIndex, into=into)

    def writeLengthsBlock(self, data):
        return self.writeBlock(lengthsRealIndex, data)

    def getActiveBank(self, lengthsBlock=None):
        if lengthsBlock is None:
            lengthsBlock = self.readLengthsBlock()
        activeBank = 0
        while lengthsBlock[activeBank] is 0 and activeBank < numBanks:
            activeBank += 1
        if activeBank < numBanks:
            return activeBank
        else:
            return None

#    @timeit('writeJson')
    def readJson(self, tagUid=None, unselect=True):
        try:
            tagUid = self.selectTag(tagUid)
            lengthsBlock = self.readLengthsBlock()
            # establish active bank from lengths block
            activeBank = self.getActiveBank(lengthsBlock)
            if activeBank is not None:
                bankLength = lengthsBlock[activeBank]   # how many bytes in the bank
                bankBytes = bytearray(bankLength)       # pre-allocate a buffer to store them
                safeIndex = activeBank * blocksPerBank  # what's the first authorable block in the bank
                nextBytePos = 0
                # read the next block from the bank, until bankBytes is filled
                blockArray = bytearray(bytesPerBlock)
                blockMv = memoryview(blockArray)
                while nextBytePos < bankLength:
                    nextRealIndex = getRealIndex(safeIndex)
                    copyLength = min(bytesPerBlock, bankLength - nextBytePos)
                    self.readBlock(nextRealIndex, into=blockArray)
                    if copyLength == bytesPerBlock:
                        bankBytes[nextBytePos:nextBytePos + copyLength] = blockArray
                    else:
                        bankBytes[nextBytePos:nextBytePos + copyLength] = blockMv[:copyLength]
                    nextBytePos += copyLength
                    safeIndex += 1
                # testing: import json; o = dict(hello="world"); b = bytes(json.dumps(o).encode("ascii")); print(json.loads(b.decode('ascii')))
                # TODO CH is there a way to avoid allocation of bytes object here to wrap bytearray
                bankBytes = bytes(bankBytes)
                return json.loads(bankBytes.decode('ascii'))
            else:
                raise AssertionError("No bank")
        finally:
            if unselect:
                self.unselectTag()
            gc.collect()

    # example ms=ticks_ms(); sack = vault.readJson(unselect=False); sack["eponapoints"]+=1; sack=vault.writeJson(sack, tagUid=vault.selectedTagUid); print(ticks_ms() - ms)

#    @timeit('writeJson')
    def writeJson(self, obj, tagUid=None, unselect=True):
        try:
            # TODO does this implicitly unselect in the case that writeJson is called 'agnostic' to tag
            tagUid = self.selectTag(tagUid)
            lengthsBlock = self.readLengthsBlock()
            activeBank = self.getActiveBank(lengthsBlock)
            if activeBank is not None:
                nextBank = (activeBank + 1) % numBanks
            else:
                nextBank = 0
            safeIndex = nextBank * blocksPerBank
            bankBytes = json.dumps(obj).encode("ascii")
            bankLength = len(bankBytes)
            nextBytePos = 0
            while nextBytePos < bankLength:
                nextRealIndex = getRealIndex(safeIndex)
                copyLength = min(bytesPerBlock, bankLength - nextBytePos)
                # TODO CH make bankBytes (json dump) a memoryview to allow 'view' to be passed to writeBlock without copy?
                self.blockBuffer[:copyLength] = bankBytes[nextBytePos:nextBytePos + copyLength]
                self.writeBlock(nextRealIndex, self.blockBuffer)
                nextBytePos += copyLength
                safeIndex += 1
            # zero blockBuffer
            nextBytePos = bytesPerBlock
            while nextBytePos > 0:
                nextBytePos -= 1
                self.blockBuffer[nextBytePos] = 0
            # populate with single byte and write as lengthsBlock
            self.blockBuffer[nextBank]=bankLength
            self.writeLengthsBlock(self.blockBuffer)

        finally:
            if unselect:
                self.unselectTag()
            gc.collect()

class CardReadIncompleteError(Exception):
    """Card was probably removed while reading"""
    pass

class CardBankMissingError(Exception):
    """Bank metadata was not found on the card"""
    pass

class CardJsonInvalidError(Exception):
    """Bank metadata found, but indicated data wasn't JSON"""
    pass

class CardJsonIncompatibleError(Exception):
    """'Userspace' error; JSON was found, but not compatible with the application"""
    pass
