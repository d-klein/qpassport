from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnectionObserver import ConsoleCardConnectionObserver

from smartcard.sw.ErrorCheckingChain import ErrorCheckingChain
from smartcard.sw.ISO7816_4ErrorChecker import ISO7816_4ErrorChecker
from smartcard.sw.SWExceptions import SWException, WarningProcessingException

from smartcard.util import toHexString
from smartcard.util import hl2bs as il2bs
from smartcard.util import bs2hl as bs2il
import os
import hashlib
from kdf import derive_doc_acc_keys, derive_key, C_ENC, C_MAC
import retail_mac
from util import hs2il,xor_lists
from des3 import TDES
from operator import xor
#from Crypto.Cipher.blockalgo import MODE_CBC
from secure_messaging import APDUProtector
from retail_mac import RMAC
from bac import run_bac
from efcom import EFCom
from dg1 import DG1
from dg2 import DG2

MRZ_DOC_NO = 'YV42109H95'
MRZ_DOB    = '6305213'
MRZ_EXP    = '1203314'
#MRZ_DOC_NO = 'C4J6R0H111'
#MRZ_DOB    = '8103206'
#MRZ_EXP    = '1808074'

MRZ_INFO = MRZ_DOC_NO + MRZ_DOB + MRZ_EXP
BAC_IV = "0000000000000000".decode('hex')

# request any card
cardtype = AnyCardType()
cardrequest = CardRequest( timeout=10, cardType=cardtype )
cardservice = cardrequest.waitforcard()

# our error checking chain
errorchain=[]
errorchain=[ ErrorCheckingChain( errorchain, ISO7816_4ErrorChecker() ) ]
cardservice.connection.setErrorCheckingChain( errorchain )

# a console tracer
observer=ConsoleCardConnectionObserver()
cardservice.connection.addObserver( observer )

# send a few apdus; exceptions will occur upon errors
cardservice.connection.connect()

# run Basic Access Control for secure messaging
(ks_enc, ks_mac, ssc) = run_bac(cardservice.connection, MRZ_INFO)

# setup secure messaging with derived keys
des_sm = TDES(ks_enc)
mac_sm = RMAC(ks_mac)
ap = APDUProtector(des_sm.enc, des_sm.dec, mac_sm.mac, ssc)
ap.debug = True

# read ef.com
efcom = EFCom()
efcom.read_ef_com(cardservice.connection, ap)
print("lds_version: "+toHexString(efcom.lds_version))
print("utf_version: "+toHexString(efcom.utf_version))
print("stored files: "+toHexString(efcom.stored_info_tags))
dg1 = DG1()
dg1.read_dg1(cardservice.connection, ap)
print("MRZ:")
print(dg1)
dg2 = DG2()
dg2.read_dg2(cardservice.connection, ap)

# write to file
if(dg2.raw_image):
    img= open("test_ef_dg2.jp2",'wb+')
    img.write(bytearray(dg2.raw_image))
    img.flush()
    img.close()

"""


k_ifd = hs2il('0B795240CB7049B01C19B33E32804F0B')
k_icc = hs2il('0B4F80323EB3191CB04970CB4052790B')
print("expected : 00 36 D2 72 F5 C3 50 AC AC 50 C3 F5 72 D2 36 00")
print("result   : "+toHexString(xor_lists(k_ifd,k_icc)))
"""
