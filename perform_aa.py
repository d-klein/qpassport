#! /usr/bin/python

from smartcard.System import readers

from card.des3 import TDES
from card.secure_messaging import SecureMessenger
from card.retail_mac import RMAC
from card.bac import run_bac
from card.dg15 import DG15
from card.aa import run_aa

from card.datagroup import read_secure
from card.tags import *
from time import time


# MRZ Info Finnland
#~ MRZ_DOC_NO = 'XP93972462'
#~ MRZ_DOB    = '7112214'
#~ MRZ_EXP    = '1108213'

# MRZ Info New Zealand silver
MRZ_DOC_NO = 'LA001586<9'
MRZ_DOB    = '6311113'
MRZ_EXP    = '1410088'

MRZ_INFO = MRZ_DOC_NO + MRZ_DOB + MRZ_EXP


# get all the available readers
r = readers()
print ("Available readers:", r)

reader = r[1]
print ("\nUsing:", reader)

connection = reader.createConnection()
connection.connect()

(ks_enc, ks_mac, ssc) = run_bac(connection, MRZ_INFO)

# setup secure messaging with derived keys
des_sm = TDES(ks_enc)
mac_sm = RMAC(ks_mac)
ap = SecureMessenger(des_sm.enc, des_sm.dec, mac_sm.mac, ssc)

    
# read ef.dg15
print("\nreading EF.DG15...")
data = read_secure(ap,connection,TAG_EF_DG15,FID_EF_DG15)

dg15 = DG15()
dg15.from_bin_data(data)

counter = 0

while (True) :
    counter +=1
    start = time()
    aasuccess = run_aa(ap, connection, dg15)
    end = time()
    print ("cycle: "+str(counter)+"AA verification:" + ("successful" if aasuccess else "failed")+", duration: "+str(end-start))



