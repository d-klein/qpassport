"""
this file is taken and adapted from the RFIDIOT project
licensed under GNU GPL
"""

from Crypto.Cipher import DES
from operator import xor
from smartcard.util import hl2bs as il2bs
from smartcard.util import bs2hl as bs2il

from card.util import pad


class RMAC:
    """
    implements retail-mac as defined in
    iso 9797-1 Algorithm 3 (Retail MAC)
    """

    DES_IV='\0\0\0\0\0\0\0\0'

    def __init__(self,key):
        """
        initialize class with key

        :param key: DES key, list of byte
        :return:
        """
        self.key = key

    def mac(self,msg):
        """
        compute r-mac of message

        :param msg: list of byte
        :return: list of byte
        """
        return self.__mac(il2bs(self.key),il2bs(msg),'')

    def __mac(self,key,message,ssc):
        # DES for all blocks
        # DES3 for last block
        tdesa= DES.new(key[0:8],DES.MODE_ECB,self.DES_IV)
        tdesb= DES.new(key[8:16],DES.MODE_ECB,self.DES_IV)
        if(ssc):
            mac= tdesa.encrypt(ssc)
        else:
            mac = self.DES_IV
        message += il2bs(pad([]))
        for y in range(len(message) / 8):
            current= message[y * 8:(y * 8) + 8]
            left= right= ''
            for x in range(len(mac)):
                left += '%02x' % ord(mac[x])
                right += '%02x' % ord(current[x])
            machex= '%016x' % xor(int(left,16),int(right,16))
            mac= tdesa.encrypt(machex.decode('hex'))
        mac= tdesb.decrypt(mac)
        return bs2il(tdesa.encrypt(mac))

"""
# some tests
# without padding
e_ifd = hs2il('72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F2')
k_mac = hs2il('7962D9ECE03D1ACD4C76089DCE131543')
print("expected: 5F 14 48 EE A8 AD 90 A7")
mc = RMAC(k_mac)
m = mc.mac(e_ifd)
print("result  : "+ toHexString((m)))

# with padding
k_mac = hs2il('F1CB1F1FB5ADF208806B89DC579DC1F8')
ssc = hs2il('887022120C06C227')
msg = hs2il('0CA4020C800000008709016375432908C044F6')
print("expected: BF 8B 92 D6 35 FF 24 F8")
mc = RMAC(k_mac)
m = mc.mac(ssc + msg)
print("result  : "+toHexString(m))

key_mac = hs2il('F1CB1F1FB5ADF208806B89DC579DC1F8')
ssc = hs2il('887022120C06C22A')
msg = hs2il('8709019FF0EC34F992265199029000')
print("expected: AD 55 CC 17 14 0B 2D ED")
mc = RMAC(key_mac)
m = mc.mac(ssc + msg)
print("result  : "+toHexString(m))

key_mac = hs2il('F1CB1F1FB5ADF208806B89DC579DC1F8')
ssc = hs2il('887022120C06C228')
msg = hs2il('99029000')
print("expected: FA 85 5A 5D 4C 50 A8 ED")
mc = RMAC(key_mac)
m = mc.mac(ssc + msg)
print("result  : "+toHexString(m))
"""