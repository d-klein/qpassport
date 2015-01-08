from card.util import Tlv_reader
import tags
from smartcard.util import toHexString

class EFCom:
    """
    read the file EF.COM and extract the lds_version string
    the unicode version string, and the list of tags
    of stored data objects

    Example:
        >>> efcom = EFCom()
        >>> efcom.read_ef_com(cardservice.connection, ap)
        >>> if(efcom.lds_version and efcom.utf_version and efcom.stored_info_tags):
        >>>     print("lds_version: "+smartcard.util.toHexStringtoHexString(efcom.lds_version))
        >>>     print("utf_version: "+smartcard.util.toHexString(efcom.utf_version))
        >>>     print("stored files: "+smartcard.util.toHexString(efcom.stored_info_tags))
    """

    def __init__(self):
        self.lds_version = None
        self.utf_version = None
        self.stored_info_tags = None

    def __str__(self):
        s = ""
        if(self.lds_version != None):
            s += "LDS Version    : "+ self.lds_version[0:2]+"."+self.lds_version[2:4]+"\n"
        if(self.utf_version != None):
            s += "Unicode Version: "+ self.utf_version[0:2]+"."+self.utf_version[2:4]+"."+self.utf_version[4:6] + "\n"
        if(self.stored_info_tags != None):
            s += ("Stored Tags    : ")
            for idx, tag in enumerate(self.stored_info_tags):
                info = tags.lookup([tag])
                if(idx == 0):
                    s += toHexString([tag]) + " "+info.upper()+"\n"
                else:
                    s += "                 "+toHexString([tag]) + " "+info.upper()+"\n"
        return s

    def read_ef_com(self,connection,ap):
        """
        :param connection: pyscard connection
        :param ap: secure messaging object for apdu protection
        :return:
        """

        # select EF.COM
        rapdu,sw1,sw2 = ap.transmit_secure(connection,0x00,0xA4,0x02,0x0C,[0x02],[0x01,0x1E],None)

        # read first two bytes of EF.COM
        rapdu,sw1,sw2 = ap.transmit_secure(connection,0x00,0xB0,0x00,0x00,None,None,[0x02])
        data = ap.parse_decrypt_do87(rapdu)

        # should be tag = 60, length = 2nd byte
        if(data[0] == 0x60):
            # read EF.COM (everything from offset 2 up to len)
            l = data[1]
            rapdu,sw1,sw2 = ap.transmit_secure(connection,0x00,0xB0,0x00,0x02,None,None,[l])
            data = ap.parse_decrypt_do87(rapdu)

            tlv = Tlv_reader([[0x5F,0x01],[0x5F,0x36],[0x5C]],data)

            self.lds_version = "".join([chr(x) for x in tlv.read([0x5F,0x01])])
            self.utf_version = "".join([chr(x) for x in tlv.read([0x5F,0x36])])
            self.stored_info_tags = tlv.read([0x5C])

        else:
            raise ValueError("could not read EF.COM (wrong tag)")



