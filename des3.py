from Crypto.Cipher import DES3
from smartcard.util import hl2bs as il2bs
from smartcard.util import bs2hl as bs2il

# the IV used for 3des according to ICAO9303
BAC_IV = "0000000000000000".decode('hex')

class TDES:

    def __init__(self,key):
        self.key = key

    def enc(self,msg):
        des3encoder = DES3.new(il2bs(self.key),DES3.MODE_CBC,BAC_IV)
        return bs2il(des3encoder.encrypt(il2bs(msg)))

    def dec(self,msg):
        des3decoder = DES3.new(il2bs(self.key),DES3.MODE_CBC,BAC_IV)
        return bs2il(des3decoder.decrypt(il2bs(msg)))

"""
# some tests (from Doc 9303)
from util import hs2il
from smartcard.util import toHexString
s = hs2il('781723860C06C2264608F919887022120B795240CB7049B01C19B33E32804F0B')
k_enc = hs2il('AB94FDECF2674FDFB9B391F85D7F76F2')
tdes = TDES(k_enc)
msg = tdes.enc(s)
print("expected : "+'72 C2 9C 23 71 CC 9B DB 65 B7 79 B8 E8 D3 7B 29 EC C1 54 AA 56 A8 79 9F AE 2F 49 8F 76 ED 92 F2')
print("result   : "+toHexString(msg))
msg2 = tdes.dec(msg)
print("expected : "+"78 17 23 86 0C 06 C2 26 46 08 F9 19 88 70 22 12 0B 79 52 40 CB 70 49 B0 1C 19 B3 3E 32 80 4F 0B")
print("result   : "+toHexString(msg2))
key = hs2il('979EC13B1CBFE9DCD01AB0FED307EAE5')
msg = hs2il('011E800000000000')
tdes = TDES(key)
print("expected : 63 75 43 29 08 C0 44 F6")
print("received : "+toHexString(tdes.enc(msg)))
"""