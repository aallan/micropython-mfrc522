import mfrc522
from machine import Pin,SPI


def do_read():
    sck =  Pin(14, mode=Pin.OUT)  # labelled 5 on nodeMCU
    mosi = Pin(13, mode=Pin.OUT)  # labelled 7 on nodeMCU
    miso = Pin(12, mode=Pin.IN)  # labelled 6 on nodeMCU
    spi = SPI(-1, baudrate=100000, polarity=0, phase=0, sck=sck, mosi=mosi, miso=miso)
    spi.init()
    rdr = mfrc522.MFRC522(spi=spi, gpioRst=0, gpioCs=2)

    while True:
        print("Place card")

        (stat, tag_type) = rdr.request(rdr.REQIDL)

        if stat == rdr.OK:

            (stat, raw_uid) = rdr.anticoll()

            if stat == rdr.OK:
                print("Detected")
                print("type: 0x%02x" % tag_type)
                print("uid: 0x%02x%02x%02x%02x" % (raw_uid[0], raw_uid[1], raw_uid[2], raw_uid[3]))
                print("")

                if rdr.select_tag(raw_uid) == rdr.OK:

                    key = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]

                    for sector in range(1, 64):
                        if rdr.auth(rdr.AUTHENT1A, sector, key, raw_uid) == rdr.OK:
                            print("data@%d: %s" % (sector, rdr.read(sector)))
                        else:
                            print("Auth err")
                    rdr.stop_crypto1()
                else:
                    print("Select failed")
