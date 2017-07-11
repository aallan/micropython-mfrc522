import gc

from machine import SPI, freq
from mfrc522 import MFRC522
from vault import BankVault, CardBankMissingError, CardReadIncompleteError, CardJsonInvalidError, CardJsonIncompatibleError

from timer import startTimer, endTimer

"""
# Objectives:

* Ensure that awaitAbsence not spuriously triggered even when a card is in fact there
* Eliminate unnecessary slowdowns from
    * selectTag calling isPresentTag() when selectTag already triggered by presence, (call is implied by readCard)
    * gc.collect() or spurious array allocations
    * repeated reauthentication against blocks
    * repeated reselect of cards
* Avoid...
    * reading card when possible
        * same card within a 'paging delay' must have same cardData as just written
    * writing card when possible
        * if cardData has not changed
"""

freq(160000000)

spi = SPI(1, baudrate=1800000, polarity=0, phase=0)
spi.init()
cardReader = MFRC522(spi=spi, gpioRst=None, gpioCs=2)
cardVault = BankVault(reader=cardReader)

# red cards are reset cards
resetUids =(b'=\xe5zR\xf0', b'=whRp', b'=eoRe', b'=\x14\x8dR\xf6', b'=\x95?R\xc5', b'=Q\xf2R\xcc')
resetCard = False

resumeMs = 10000

cardCache = None
cardData = None

version = 1
filler = "The Quick Brown Fox Jumped over the Lazy Dog. Nymphs vex quick dwarf jog blitz."
startData = {"version":version, "counter":0 ,"filler":filler}

while True:
    gc.collect()
    if cardCache is not None: # hope to resume
        presentUid = cardVault.awaitPresence(resumeMs)
    else:
        presentUid = cardVault.awaitPresence()

    if presentUid is not None:
        print("CARD PRESENT")
    else: # resumeMs timeout was hit
        if cardCache is not None:
            print("RESUME ABANDONED")
            cardCache = None
            continue

    try:
        startTimer('handleCard')

        cardUid = cardVault.selectTag()

        if cardUid in resetUids:
            resetCard = True
            cardVault.awaitAbsence()
            continue

        if resetCard:
            cardData = dict(startData)
        elif cardCache is not None:
            if cardUid == cardCache["cardUid"]:
                cardData = cardCache["cardData"]
                print("RESUMED")
            else:
                print("RESUME FAILED")
            cardCache = None  # discard cached data from previous cycle (implicitly after resumeMs)

        if cardData is None:
            try:
                cardData = cardVault.readJson(tagUid=cardUid, unselect=False)
                if "version" not in cardData or cardData["version"] != version:
                    raise CardJsonIncompatibleError("Card data has no counter (previously used for different application)")
                print("CARD LOADED")
            except CardReadIncompleteError:
                print("Card removed before read complete")
                continue
            except (CardBankMissingError, CardJsonInvalidError, CardJsonIncompatibleError):
                print("Card has no acceptable Json, populating card Json from startData")
                cardData = dict(startData)

        print("Previous counter {}".format(cardData["counter"]))

        print("Incrementing counter")
        cardData["counter"] += 1

        try:
            cardWritten = dict(cardData)
            cardVault.writeJson(cardData, tagUid=cardUid, unselect=True)
            cardCache = dict(cardUid=cardUid, cardData=cardData)
        except:
            print("Error; discarding write. One of...")
            print("Card identity not the intended card to be written")
            print("Card removed before write complete")

        # TODO try this to avoid error counting in awaitAbsence (meaning two presence cycles needed to detect)
        #cardVault.reader.reset()

    finally:
        endTimer('handleCard')

    cardVault.awaitAbsence()

    print("CARD REMOVED")
