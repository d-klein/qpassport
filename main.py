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

    # read ef.com
    print("\nreading EF.COM...")
    efcom = EFCom()
    efcom.read_ef_com(cardservice.connection, ap)
    print(str(efcom))

    print("reading DG1...")
    dg1 = DG1()
    dg1.read_dg1(cardservice.connection, ap)
    print(str(dg1))

    print("\nreading DG2... (facial image)")
    dg2 = DG234(2,0x75)
    dg2.read_dg234(cardservice.connection, ap)
    for idx,bit in enumerate(dg2.bio_info_templates):
        print(str(bit))
        if(bit.jp2):
            fn = MRZ_DOC_NO+"_DG2_"+str(idx)+".jp2"
            print("JPEG2000  present  : Yes, saving as "+fn+"\n")
            img= open(fn,'wb+')
            img.write(bytearray(bit.jp2))
            img.flush()
            img.close()
        if(bit.jpeg):
            fn = "DG2_"+MRZ_DOC_NO+"_"+str(idx)+".jpg"
            print("JPEG      present  : Yes, saving as "+fn+"\n")
            img= open(fn,'wb+')
            img.write(bytearray(bit.jp2))
            img.flush()
            img.close()

    print("\nreading DG2... (facial image)")
    dg2 = DG234(2,0x75)
    dg2.read_dg234(cardservice.connection, ap)

    #print("\nprobing for DG3... (fingerprints)")
    #try:
    #    dg3 = DG234(3,0x63)
    #    dg3.read_dg234(cardservice.connection, ap)
    #    for idx,bit in enumerate(dg3.bio_info_templates):
    #        fn = "DG3_"+MRZ_DOC_NO+"_"+str(idx)+".raw"
    #        print("saving (raw) biometric data block as: "+fn+"\n")
    #        img= open(fn,'wb+')
    #        img.write(bytearray(bit.bio_data))
    #        img.flush()
    #        img.close()
    #except ValueError as s:
    #    print(s)
    #except smartcard.sw.SWExceptions.CheckingErrorException as s:
    #    msg = str(s)
    #    print(msg)
    #    if('Security status not satisfied!' in msg):
    #        print("most likely cause: fingerprints are crypto-protected")
    #    if('Secure messaging data object incorrect' in msg):
    #        print("most likely cause: DG3 doesn't exist")



    #print("\nprobing for DG4... (iris)")
    #try:
    #    dg4 = DG234(4,0x76)
    #    dg4.read_dg234(cardservice.connection, ap)
    #    for idx,bit in enumerate(dg4.bio_info_templates):
    #        fn = "DG3_"+MRZ_DOC_NO+"_"+str(idx)+".raw"
    #        print("saving (raw) biometric data block as: "+fn+"\n")
    #        img= open(fn,'wb+')
    #        img.write(bytearray(bit.bio_data))
    #        img.flush()
    #        img.close()
    #except ValueError as s:
    #    print(s)
    #except smartcard.sw.SWExceptions.CheckingErrorException as s:
    #    msg = str(s)
    #    print(msg)
    #    if('Security status not satisfied!' in msg):
    #        print("most likely cause: iris pattern are crypto-protected")
    #    if('Secure messaging data object incorrect' in msg):
    #        print("most likely cause: DG4 doesn't exist")


    for i in xrange(6,8):
        s_of_i = str(i)
        print("\nprobing for DG"+s_of_i+"...")
        try:
            dg5 = DG567(i)
            dg5.read_dg567(cardservice.connection, ap)
            for idx,t in enumerate(dg5.image_templates):
                if(t.portrait):
                    fn = "DG"+s_of_i+"_"+MRZ_DOC_NO+"_portrait_"+str(idx)+".jpg"
                print("saving portrait as: "+fn+"\n")
                img= open(fn,'wb+')
                img.write(bytearray(t.portrait))
                img.flush()
                img.close()
                if(t.signature):
                    fn = "DG"+s_of_i+"_"+MRZ_DOC_NO+"_disp_sig_"+str(idx)+".jpg"
                    print("saving displayed signature as: "+fn+"\n")
                    img= open(fn,'wb+')
                    img.write(bytearray(t.signature))
                    img.flush()
                    img.close()
        except ValueError as s:
            print(s)
        except smartcard.sw.SWExceptions.CheckingErrorException as s:
            msg = str(s)
            print(msg)
            if('Security status not satisfied!' in msg):
                print("most likely cause: data are crypto-protected")
            if('Secure messaging data object incorrect' in msg):
                print("most likely cause: DG doesn't exist")
            if('Referenced data not found' in msg):
                print("most likely cause: DG doesn't exist")



except CardRequestTimeoutException:
    print('time-out: no card inserted during last 10s')

