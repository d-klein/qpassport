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
import smartcard
from card.datagroup import read_secure,read_unencrypted
from card.tags import *
from pyasn1.codec.ber import encoder,decoder


MRZ_DOC_NO = 'YV42109H95'
MRZ_DOB    = '6305213'
MRZ_EXP    = '1203314'
#MRZ_DOC_NO = 'C4J6R0H111'
#MRZ_DOB    = '8103206'
#MRZ_EXP    = '1808074'

DEBUG = False

print("\naccessing e-passport with:")
print("document number: "+str(MRZ_DOC_NO))
print("date of birth  : " + str(MRZ_DOB))
print("expiration date: "+str(MRZ_EXP))

MRZ_INFO = MRZ_DOC_NO + MRZ_DOB + MRZ_EXP
BAC_IV = "0000000000000000".decode('hex')
print("MRZ INFO: "+MRZ_INFO)
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

    # read ef.cardaccess
    print("\nreading EF.CardAccess")
    data = read_unencrypted(cardservice.connection,FID_EF_CARD_ACCESS)
    print("received: "+toHexString(data))
    foo = decoder.decode(smartcard.util.hl2bs(data))
    print(foo)

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
    data = read_secure(ap,cardservice.connection,TAG_EF_COM,FID_EF_COM)
    efcom = EFCom()
    efcom.from_bin_data(data)
    print(str(efcom))

    print("reading DG1...")
    data = read_secure(ap,cardservice.connection,TAG_EF_DG1,FID_EF_DG1)
    dg1 = DG1()
    dg1.from_bin_data(data)
    print(str(dg1))

    print("\nreading DG2... (facial image)")
    data = read_secure(ap,cardservice.connection,TAG_EF_DG2,FID_EF_DG2)
    dg2 = DG234(FID_EF_DG2)
    dg2.from_bin_data(data)
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

    try:
        print("\nprobing for DG3... (fingerprints)")
        data = read_secure(ap,cardservice.connection,TAG_EF_DG3,FID_EF_DG3)
        dg3 = DG234(FID_EF_DG3)
        dg3.from_bin_data(data)
        for idx,bit in enumerate(dg3.bio_info_templates):
            fn = "DG3_"+MRZ_DOC_NO+"_"+str(idx)+".raw"
            print("saving (raw) biometric data block as: "+fn+"\n")
            raw= open(fn,'wb+')
            raw.write(bytearray(bit.bio_data))
            raw.flush()
            raw.close()
    except smartcard.sw.SWExceptions.CheckingErrorException as s:
        msg = str(s)
        print(msg)
        if('Security status not satisfied!' in msg):
            print("most likely cause: fingerprints are crypto-protected")


    print("\nprobing for DG4... (iris)")
    try:
        data = read_secure(ap,cardservice.connection,TAG_EF_DG4,FID_EF_DG4)
        dg4 = DG234(FID_EF_DG4)
        dg4.from_bin_data(data)
        for idx,bit in enumerate(dg4.bio_info_templates):
            fn = "DG3_"+MRZ_DOC_NO+"_"+str(idx)+".raw"
            print("saving (raw) biometric data block as: "+fn+"\n")
            img= open(fn,'wb+')
            img.write(bytearray(bit.bio_data))
            img.flush()
            img.close()
    except ValueError as s:
        print(s)
    except smartcard.sw.SWExceptions.CheckingErrorException as s:
        msg = str(s)
        print(msg)
        if('Security status not satisfied!' in msg):
            print("most likely cause: iris pattern are crypto-protected")

    FIDS = [FID_EF_DG5,FID_EF_DG6,FID_EF_DG7,FID_EF_DG8]
    TIDS = [TAG_EF_DG5,TAG_EF_DG6,TAG_EF_DG7,TAG_EF_DG8,]
    for i in xrange(5,8):
        s_of_i = str(i)
        print("\nprobing for DG"+s_of_i+"...")
        try:
            dgi = DG567(FIDS[i-5])
            data = read_secure(ap,cardservice.connection,FIDS[i-5],TIDS[i-5])
            dgi.from_bin_data(data)
            for idx,t in enumerate(dgi.image_templates):
                if(t.portrait):
                    fn = "DG"+s_of_i+"_"+MRZ_DOC_NO+"_portrait_"+str(idx)+".jpg"
                print("saving portrait as: "+fn+"\n")
                f= open(fn,'wb+')
                f.write(bytearray(t.portrait))
                f.flush()
                f.close()
                if(t.signature):
                    fn = "DG"+s_of_i+"_"+MRZ_DOC_NO+"_disp_sig_"+str(idx)+".jpg"
                    print("saving displayed signature as: "+fn+"\n")
                    f= open(fn,'wb+')
                    f.write(bytearray(t.signature))
                    f.flush()
                    f.close()
        except ValueError as s:
            print(s)
        except smartcard.sw.SWExceptions.CheckingErrorException as s:
            msg = str(s)
            print(msg)
            if('Security status not satisfied!' in msg):
                print("most likely cause: data are crypto-protected")


except CardRequestTimeoutException:
    print('time-out: no card inserted during last 10s')

