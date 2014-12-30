from util import Tlv_reader
from smartcard.util import toHexString
from util import il2hs

class EFCom:
    def __init__(self):
        self.lds_version = None
        self.utf_version = None
        self.stored_info_tags = None


def read_ef_com(connection,ap):

    # select EF.COM
    ap.inc_ssc()
    papdu = ap.protectAPDU(0x00,0xA4,0x02,0x0C,[0x02],[0x01,0x1E],None)
    rapdu,sw1,sw2 = connection.transmit( papdu )

    ap.inc_ssc()
    ap.verifyRAPDU(rapdu+[sw1,sw2])

    # read first two bytes of EF.COM
    ap.inc_ssc()
    papdu = ap.protectAPDU(0x00,0xB0,0x00,0x00,None,None,[0x02])
    rapdu,sw1,sw2 = connection.transmit( papdu )

    ap.inc_ssc()
    ap.verifyRAPDU(rapdu+[sw1,sw2])

    data = ap.parse_deccrypt_do87(rapdu)
    print("received two bytes of ef.com: "+toHexString(data) )

    # should be tag = 60, length = 2nd byte
    if(data[0] == 0x60):
        # read EF.COM (everything from offset 2 up to len)
        l = data[1]
        print("len: "+toHexString([l]))
        ap.inc_ssc()
        papdu = ap.protectAPDU(0x00,0xB0,0x00,0x02,None,None,[l])
        rapdu,sw1,sw2 = connection.transmit( papdu )

        ap.inc_ssc()
        ap.verifyRAPDU(rapdu+[sw1,sw2])

        data = ap.parse_deccrypt_do87(rapdu)
        tlv = Tlv_reader([[0x5F,0x01],[0x5F,0x36],[0x5C]],data)
        efcom = EFCom()
        efcom.lds_version = tlv.read([0x5F,0x01])
        efcom.utf_version = tlv.read([0x5F,0x36])
        efcom.stored_info_tags = tlv.read([0x5C])
        return efcom

    else:
        raise ValueError("could not read EF.COM (wrong tag)")



