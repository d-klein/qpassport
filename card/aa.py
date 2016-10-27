from binascii import hexlify, unhexlify
from hashlib import sha1
from os import urandom


def run_aa(sm, connection, dg15):
    
    # Generate random for INTERNAL AUTHENTICATE command    
    aarandom = bytearray(urandom(8))
    
    rapdu,sw1,sw2 = sm.transmit_secure(connection,0x00,0x88,0x00,0x00,[0x08],aarandom,[0x00])
    data = sm.parse_decrypt_do87(rapdu)

    if (data):        
        message = recoverMessage(data, dg15)
        #~ print ("Recoverd Message:\n"+hexlify(message))
        
        if (message[127] ==0xbc):
            sha1Gen = sha1()
            carddigest = message[107:127]
            #~ print ("Card Digest:\n"+ hexlify(carddigest))
            
            m1 = message[1:107]            
            #~ print ("\nM1:\n"+ hexlify(m1))
            
            m = m1 + aarandom
            #~ print ("\nM:\n"+ hexlify(m))
            
            mydigest = sha1Gen.update(buffer(m))
            mydigest = sha1Gen.digest()            
            #~ print ("\nMy Digest:\n"+ hexlify(mydigest))
            if (carddigest == mydigest): return True
        else: 
            # currently we don't support any other digest then SHA1
            return False
    return False


def recoverMessage(cMessage, dg15):
    cipherMessage = (int(hexlify(bytearray(cMessage)),16))
    exponent = (int(hexlify(bytearray(dg15.publicExponent)),16))
    modulus = (int(hexlify(bytearray(dg15.modulus)),16))
    recoveredMessage = pow(cipherMessage, exponent, modulus)
    return bytearray(unhexlify(format(recoveredMessage, 'x')))
