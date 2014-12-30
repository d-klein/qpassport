from kdf import derive_doc_acc_keys, derive_key, C_ENC, C_MAC
from des3 import TDES
from retail_mac import RMAC
import os
from util import xor_lists
from smartcard.sw.SWExceptions import SWException

def run_bac(connection,mrz):

    try:
        # select ICAO passport application
        SELECT_ICAO_AID = [0x00, 0xA4, 0x04, 0x0C, 0x07, 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01]
        apdu = SELECT_ICAO_AID
        response, sw1, sw2 = connection.transmit( apdu )

        # get 8 byte random number from chip
        GET_CHALLENGE = [0x00, 0x84, 0x00, 0x00, 0x08]
        apdu = GET_CHALLENGE
        response, sw1, sw2 = connection.transmit( apdu )
        rnd_icc = response

        # generate 8 byte random and 16 byte random
        rnd_ifd = list(bytearray(os.urandom(8)))
        k_ifd = list(bytearray(os.urandom(16)))

        # concatenate to get s
        s = rnd_ifd + rnd_icc + k_ifd

        # derive_key k_enc, k_mac
        k_enc, k_mac = derive_doc_acc_keys(mrz)

        # encrypt s with 3des with key k_enc
        des3 = TDES(k_enc)
        e_ifd = des3.enc(s)

        # calculate mac over encrypted s = e_ifd
        rmc = RMAC(k_mac)
        m_ifd = rmc.mac(e_ifd)

        # build cmd for mutual authenticate
        cmd = e_ifd + m_ifd
        assert(len(cmd)==0x28)
        MUTUAL_AUTH = [0x00, 0x82, 0x00, 0x00, 0x28] + cmd + [0x28]
        apdu = MUTUAL_AUTH
        response, sw1, sw2 = connection.transmit( apdu )

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
        ssc = rnd_icc[4:8] + rnd_ifd[4:8]

        return (ks_enc, ks_mac, ssc)

    except SWException, e:
        print str(e)