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

MRZ_DOC_NO = 'YV42109H95'
MRZ_DOB    = '6305213'
MRZ_EXP    = '1203314'
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

try:
    # select ICAO passport application
    SELECT_ICAO_AID = [0x00, 0xA4, 0x04, 0x0C, 0x07, 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01]
    apdu = SELECT_ICAO_AID
    response, sw1, sw2 = cardservice.connection.transmit( apdu )

    # get 8 byte random number from chip
    GET_CHALLENGE = [0x00, 0x84, 0x00, 0x00, 0x08]
    apdu = GET_CHALLENGE
    response, sw1, sw2 = cardservice.connection.transmit( apdu )   
    rnd_icc = response
    print("challenge received: "+toHexString(rnd_icc))
    
    # generate 8 byte random and 16 byte random
    rnd_ifd = list(bytearray(os.urandom(8)))
    print("rnd ifd: "+toHexString(rnd_ifd))
    k_ifd = list(bytearray(os.urandom(16)))
    print("k_ifd: "+toHexString(rnd_ifd))

    # concatenate to get s
    s = rnd_ifd + rnd_icc + k_ifd
    
    # derive_key k_enc, k_mac
    k_enc, k_mac = derive_doc_acc_keys(MRZ_INFO)

    # print("derived k_enc: "+(k_enc))
    print("as bytes :"+str(bytes(k_enc)))
    print("len: "+str(len(str(k_enc))))

    # encrypt s with 3des with key k_enc
    des3 = TDES(k_enc)
    e_ifd = des3.enc(s)
    print("encrypted s: "+toHexString(e_ifd))

    # calculate mac over encrypted s = e_ifd
    rmc = RMAC(k_mac)
    m_ifd = rmc.mac(e_ifd)
    print("m_ifd : "+toHexString(m_ifd))

    # build cmd for mutual authenticate
    cmd = e_ifd + m_ifd
    assert(len(cmd)==0x28)
    MUTUAL_AUTH = [0x00, 0x82, 0x00, 0x00, 0x28] + cmd + [0x28]
    apdu = MUTUAL_AUTH
    response, sw1, sw2 = cardservice.connection.transmit( apdu )
    
    # decrypt response, check rnd_ifd
    response_raw = des3.dec(response)
    received_rnd_ifd = response_raw[8:16]
    if(not received_rnd_ifd == rnd_ifd):
        raise ValueError("Received R_IFD does not correspond to sent R_IFD")

    k_icc = response_raw[16:32]
    k_seed = xor_lists(k_icc,k_ifd)

    # derive session keys for secure messaging
    ks_enc = derive_key(k_seed,C_ENC)
    ks_mac = derive_key(k_seed,C_MAC)

    # calculate SSC
    print("rnd_icc: "+toHexString(rnd_icc))
    print("rnd_ifd: "+toHexString(rnd_ifd))
    ssc = rnd_icc[4:8] + rnd_ifd[4:8]
    print("ssc:    : "+toHexString(ssc))

    # create protected apdus
    des_sm = TDES(ks_enc)
    mac_sm = RMAC(ks_mac)
    ap = APDUProtector(des_sm.enc, des_sm.dec, mac_sm.mac, ssc)

    ap.inc_ssc()
    print("constructing papdu1")
    papdu = ap.protectAPDU(0x00,0xA4,0x02,0x0C,[0x02],[0x01,0x1E],None)
    print("apdu: "+toHexString(papdu))
    rapdu,sw1,sw2 = cardservice.connection.transmit( papdu )

    ap.inc_ssc()
    ap.verifyRAPDU(rapdu+[sw1,sw2])

    ap.inc_ssc()

    papdu = ap.protectAPDU(0x00,0xB0,0x00,0x00,None,None,[0x04])
    rapdu,sw1,sw2 = cardservice.connection.transmit( papdu )

    ap.inc_ssc()
    ap.verifyRAPDU(rapdu+[sw1,sw2])

    data = ap.parse_deccrypt_do87(rapdu)

    print("received data: "+toHexString(data))




except SWException, e:
    print str(e)

"""


k_ifd = hs2il('0B795240CB7049B01C19B33E32804F0B')
k_icc = hs2il('0B4F80323EB3191CB04970CB4052790B')
print("expected : 00 36 D2 72 F5 C3 50 AC AC 50 C3 F5 72 D2 36 00")
print("result   : "+toHexString(xor_lists(k_ifd,k_icc)))
"""
