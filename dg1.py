from util import Tlv_reader
from smartcard.util import toHexString
from util import il2hs

class DG1:
    def __init__(self):
        self.mrz_bin = None
        self.mrz_line1 = None
        self.mrz_line2 = None
        self.mrz_line3 = None

    def __str__(self):
        out = ""
        if(self.mrz_line1):
            out += self.mrz_line1
        if(self.mrz_line2):
            out += "\n"+self.mrz_line2
        if(self.mrz_line3):
            out += "\n"+self.mrz_line3
        return out

    def read_dg1(self,connection,ap):

        # select DG1
        ap.transmit_secure(connection,0x00,0xA4,0x02,0x0C,[0x02],[0x01,0x01],None)

        ap.inc_ssc()
        papdu = ap.protectAPDU(0x00,0xA4,0x02,0x0C,[0x02],[0x01,0x01],None)
        rapdu,sw1,sw2 = connection.transmit( papdu )

        ap.inc_ssc()
        ap.verifyRAPDU(rapdu+[sw1,sw2])

        # read first two bytes of DG1
        ap.inc_ssc()
        papdu = ap.protectAPDU(0x00,0xB0,0x00,0x00,None,None,[0x02])
        rapdu,sw1,sw2 = connection.transmit( papdu )

        ap.inc_ssc()
        ap.verifyRAPDU(rapdu+[sw1,sw2])

        data = ap.parse_deccrypt_do87(rapdu)
        print("received two bytes of DG1: "+toHexString(data) )


        # should be tag = 60, length = 2nd byte
        if(data[0] == 0x61):
            # read DG1 (everything from offset 2 up to len)
            l = data[1]
            print("len: "+toHexString([l]))
            ap.inc_ssc()
            papdu = ap.protectAPDU(0x00,0xB0,0x00,0x02,None,None,[l])
            rapdu,sw1,sw2 = connection.transmit( papdu )

            ap.inc_ssc()
            ap.verifyRAPDU(rapdu+[sw1,sw2])

            data = ap.parse_deccrypt_do87(rapdu)
            #print("dg1 : "+toHexString(data))

            tlv = Tlv_reader([[0x5F,0x1F]],data)
            self.mrz_bin = tlv.read([0x5F,0x1F])
            mrz_txt = ''.join([chr(x) for x in self.mrz_bin])
            if(len(mrz_txt) == 90):
                # document is td1 (i.e. id-card): 3 lines of 30 char each
                self.mrz_line1 = mrz_txt[0:30]
                self.mrz_line2 = mrz_txt[30:60]
                self.mrz_line3 = mrz_txt[60:90]
            elif(len(mrz_txt) == 72):
                # a visa (two lines of 36)
                self.mrz_line1 = mrz_txt[0:36]
                self.mrz_line2 = mrz_txt[36:72]
            elif(len(mrz_txt) == 88):
                # passport (two lines of 44)
                self.mrz_line1 = mrz_txt[0:44]
                self.mrz_line2 = mrz_txt[44:88]
            else:
                l = len(mrz_txt)
                raise ValueError("unknown MRZ of length "+str(l)+": "+str(mrz_txt))

        else:
            raise ValueError("could not read EF.COM (wrong tag)")
