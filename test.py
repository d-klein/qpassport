#!/usr/bin/python2
__author__ = 'Dominik Klein'

from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnectionObserver import ConsoleCardConnectionObserver
from smartcard.sw.ErrorCheckingChain import ErrorCheckingChain
from smartcard.sw.ISO7816_4ErrorChecker import ISO7816_4ErrorChecker
from smartcard.util import toHexString
from smartcard.Exceptions import CardRequestTimeoutException
from card.des3 import TDES
from card.secure_messaging import SecureMessenger
from card.retail_mac import RMAC
from card.bac import run_bac
from card.efcom import EFCom
from card.dg1 import DG1
from card.dg234 import DG234
from card.dg567 import DG567
import card.tags
import smartcard

#MRZ_DOC_NO = 'YV42109H95'
#MRZ_DOB    = '6305213'
#MRZ_EXP    = '1203314'
MRZ_DOC_NO = 'C4J6R0H111'
MRZ_DOB    = '8103206'
MRZ_EXP    = '1808074'

DEBUG = True

print("\naccessing e-passport with:")
print("document number: "+str(MRZ_DOC_NO))
print("date of birth  : " + str(MRZ_DOB))
print("expiration date: "+str(MRZ_EXP))

MRZ_INFO = MRZ_DOC_NO + MRZ_DOB + MRZ_EXP
BAC_IV = "0000000000000000".decode('hex')

# request any card
cardtype = AnyCardType()
cardrequest = CardRequest( timeout=10, cardType=cardtype )
try:
    cardservice = cardrequest.waitforcard()

    # our error checking chain
    errorchain=[]
    errorchain=[ ErrorCheckingChain( errorchain, ISO7816_4ErrorChecker() ) ]
    cardservice.connection.setErrorCheckingChain( errorchain )

    # a console tracer
    if(DEBUG):
        observer=ConsoleCardConnectionObserver()
        cardservice.connection.addObserver( observer )

    # send a few apdus; exceptions will occur upon errors
    cardservice.connection.connect()

    # run Basic Access Control for secure messaging
    (ks_enc, ks_mac, ssc) = run_bac(cardservice.connection, MRZ_INFO)

    # setup secure messaging with derived keys
    des_sm = TDES(ks_enc)
    mac_sm = RMAC(ks_mac)
    ap = SecureMessenger(des_sm.enc, des_sm.dec, mac_sm.mac, ssc)
    if(DEBUG):
        ap.debug = True

    print("probing for DG6")
    try:
        rapdu, sw, sw2 = ap.transmit_secure(cardservice.connection,0x00,0xA4,0x02,0x0C,[0x02],[0x01,0x06],None)
    except smartcard.sw.SWExceptions.CheckingErrorException as s:
        print("error probing for DG6: ")
        print(s)
    print("selecting AID")
    #ap.inc_ssc()
    rapdu, sw1, sw2 = ap.transmit_secure(cardservice.connection, 0x00, 0xA4, 0x04, 0x0C, [0x07],[0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01], None)
    print("selecting DG2")
    rapdu, sw, sw2 = ap.transmit_secure(cardservice.connection,0x00,0xA4,0x02,0x0C,[0x02],[0x01,0x02],None)


except CardRequestTimeoutException:
    print('time-out: no card inserted during last 10s')

