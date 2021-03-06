from smartcard.util import toHexString
import smartcard

from util import pad,hs2il, set_bit_at,ber_tlv_len,dec_ber_tlv_len,unpad


class SecureMessenger:
    """
    implements secure messaging as specified in ICAO Doc 9303

    Example:
    Initialize
        >>> key_mac = hs2il('F1CB1F1FB5ADF208806B89DC579DC1F8')
        >>> ssc = hs2il('887022120C06C227')
        >>> des = TDES(key_enc)
        >>> rmac = RMAC(key_mac)
        >>> ap = SecureMessenger(des.enc, des.dec, rmac.mac,ssc)

    Set debug = True, to trace (decrypted) commands
    Transmit:
        >>> rapdu,sw1,sw2 = ap.transmit_secure(connection,0x00,0xB0,0x00,0x00,None,None,[0x06])

    To decode, if response apdu contains do87:
        >>> data = ap.parse_deccrypt_do87(rapdu)
    """
    def __init__(self,func_des_enc,func_des_dec,func_mac,ssc):
        self.des3enc = func_des_enc
        self.des3dec = func_des_dec
        self.mac     = func_mac
        self.ssc     = ssc
        self.debug   = False

    def inc_ssc(self):
        self.__inc_ssc()

    def __inc_ssc(self):
        done = False
        idx = len(self.ssc) - 1
        while( not done):
            if(idx < 0):
                self.ssc = [1] + self.ssc
                done = True
            else:
                if(self.ssc[idx] < 255):
                    self.ssc[idx] += 1
                    done = True
                else:
                    self.ssc[idx] = 0
                    idx -= 1

    def __build_do87(self,data):
        # encode data
        enc = self.des3enc(pad(data))
        # encode length of: encrypted data + one more for
        #                   padding content indicator
        l = ber_tlv_len(len(enc)+1)
        return [0x87] + l + [0x01] + enc

    def __build_do97(self,le):
        do97 = [0x97] + ber_tlv_len(len(le)) + le
        return do97

    def __trace_command(self,cla,ins,p1,p2,lc,data,le):
        cmd = [cla, ins, p1, p2]
        if(lc):
            cmd += lc
        if(data):
            cmd += data
        if(le):
            cmd += le
        print(">! "+toHexString(cmd))

    def __trace_response(self,data):
        if(data):
            print("<! "+toHexString(data))
        else:
            print("<! (no decoded data)")

    def __protectAPDU(self,cla,ins,p1,p2,lc,data,le):
        if(self.debug):
            self.__trace_command(cla,ins,p1,p2,lc,data,le)
        #mask cla
        mcla = set_bit_at(set_bit_at(cla,3,1),2,1)
        #construct cmd
        cmd = [mcla, ins, p1, p2]
        do87 = []
        if(data):
            do87 = self.__build_do87(data)
        do97 = []
        if(le):
            do97 = self.__build_do97(le)
        to_be_macced = self.ssc + cmd + [0x80, 0x00, 0x00, 0x00] + do87 + do97
        cc = self.mac(to_be_macced)
        do8e = [0x8E,0x08] + cc
        lc = hs2il("%02x" % (len(do87) + len(do97) + len(do8e)))
        return cmd + lc + do87 + do97 + do8e + [0x00]

    def parse_decrypt_do87(self,rapdu):
        """
        decrypt a do87 object if contained in the (encrypted) response apdu
        :param rapdu: the encrypted response apdu
        :return: the decrypted data
        """
        if(not rapdu[0] == 0x87):
            if(self.debug):
                self.__trace_response(None)
            return None
        else:
            head, enc_data = dec_ber_tlv_len(rapdu[1:])
            data = unpad(self.des3dec(enc_data[1:]))
            if(self.debug):
                self.__trace_response(data)
            return data

    def __decode_do87(self,rapdu):
        head, data = dec_ber_tlv_len(rapdu[1:])
        return [0x87] + head + data

    def __verifyRAPDU(self,rapdu):
        do99 = rapdu[-16:-12]
        do8e = rapdu[-12:]
        cc = rapdu[-10:-2]
        do87 = []
        if(rapdu[0] == 0x87):
            do87 = self.__decode_do87(rapdu)
        if not (cc == self.mac(self.ssc + do87 + do99)):
            raise ValueError("Secure Messaging Error: MAC could not be verified!")

    def transmit_secure(self,connection,cla,ins,p1,p2,lc,data,le):
        """
        If any of input parameters are not needed, then set
        to None

        :param connection: pyscard connection
        :param cla: cla byte
        :param ins: ins byte
        :param p1: p1 byte
        :param p2: p2 byte
        :param lc: list of one or more lc bytes
        :param data: list of data bytes
        :param le: list of one or more le bytes
        :return: triple of (encrypted) response apdu, sw1 and sw2
        """
        self.__inc_ssc()
        papdu = self.__protectAPDU(cla,ins,p1,p2,lc,data,le)
        self.__inc_ssc()
        rapdu,sw1,sw2 = connection.transmit( papdu )
        self.__verifyRAPDU(rapdu+[sw1,sw2])
        return rapdu,sw1,sw2


"""
# some tests
# with do87 & do8e, but no do97
from smartcard.util import toHexString
from des3 import TDES
from retail_mac import RMAC
key_enc = hs2il('979EC13B1CBFE9DCD01AB0FED307EAE5')
key_mac = hs2il('F1CB1F1FB5ADF208806B89DC579DC1F8')
ssc = hs2il('887022120C06C227')
print("to be macced: 0C A4 02 0C 80 00 00 00 87 09 01 63 75 43 29 08 C0 44 F6")
des = TDES(key_enc)
rmac = RMAC(key_mac)
a = SecureMessenger(des.enc, des.dec, rmac.mac,ssc)
b = a.protectAPDU(0x00,0xA4,0x02,0x0C,[0x02],[0x01,0x1E],None)
print("expected  : 0C A4 02 0C 15 87 09 01 63 75 43 29 08 C0 44 F6 8E 08 BF 8B 92 D6 35 FF 24 F8 00")
print("calculated: "+toHexString(b))

# with do97 and do8e, but not do87
a.inc_ssc()
a.inc_ssc()
c = a.protectAPDU(0x00,0xB0,0x00,0x00,None,None,[0x04])
print("expected  : 0C B0 00 00 0D 97 01 04 8E 08 ED 67 05 41 7E 96 BA 55 00")
print("calculated: "+toHexString(c))
a.inc_ssc()
rapdu = hs2il('8709019FF0EC34F9922651990290008E08AD55CC17140B2DED9000')
res = a.verifyRAPDU(rapdu)
print("verified RAPDU: "+str(res))
print("expeced dec do87: 60 14 5F 01")
print("decoded d87     : "+toHexString(a.parse_deccrypt_do87(rapdu)))
"""