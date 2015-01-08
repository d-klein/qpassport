from card.util import get_ber_tlv_len, dec_ber_tlv_len, make_offset

def get_raw_image(seq):
    #
    # seek to first biometric data block
    idx = 0
    while(not (seq[idx] == 0x5F and seq[idx+1] == 0x2E)):
        idx += 1
    head, dec = dec_ber_tlv_len(seq[idx+2:])
    # seek to start of jp2 image and return
    # sequence until end of biometric data block
    idx = 0
    while(idx < len(seq) - 12 and
            (not (dec[idx] == 0x00
            and dec[idx+1] == 0x00
            and dec[idx+2] == 0x00
            and dec[idx+3] == 0x0C
            and dec[idx+4] == 0x6a
            and dec[idx+5] == 0x50
            and dec[idx+6] == 0x20
            and dec[idx+7] == 0x20
            and dec[idx+8] == 0x0d
            and dec[idx+9] == 0x0a
            and dec[idx+10] == 0x87
            and dec[idx+11] == 0x0a))):
        idx += 1
    return dec[idx:]

class DG2:
    """
    given a pyscard connection and a secure messenger,
    read dg2 and extract the jp2 image file

    Example:
        >>> dg2 = DG2()
        >>> dg2.read(connection, secure_messenger)
        >>> if(dg2.raw_image):
        >>>     img= open("portrait.jp2",'wb+')
        >>>     img.write(bytearray(dg2.raw_image))
        >>>     img.flush()
        >>>     img.close()

    """
    def __init__(self):
        self.raw_image = None

    def __str__(self): pass

    def read_dg2(self,connection,ap):
        """
        reads jp2 image from dg2 and stores list of byte
        in self.raw_image

        :param connection: pyscard connection
        :param ap: secure messaging object for apdu protection
        :return:
        """

        # select DG2
        ap.transmit_secure(connection,0x00,0xA4,0x02,0x0C,[0x02],[0x01,0x02],None)

        # read length (first 6 bytes) of DG2 to get file length
        rapdu,sw1,sw2 = ap.transmit_secure(connection,0x00,0xB0,0x00,0x00,None,None,[0x06])
        data = ap.parse_decrypt_do87(rapdu)

        if(data[0 == 0x75]):
            # read DG2
            # decode length of dg2
            l,len_of_l = get_ber_tlv_len(data[1:])
            data_block = []
            # offset = one byte of 0x75 + length of length field itself
            offset = len_of_l + 1
            iterations = l // 255
            last_len = l % 255
            # read dg2
            for i in xrange(0,iterations):
                p1,p2 = make_offset(offset)
                rapdu,sw1,sw2 = ap.transmit_secure(connection,0x00,0xB0,p1,p2,None,None,[255])
                data = ap.parse_decrypt_do87(rapdu)
                data_block.extend(data)
                offset += 255
            p1,p2 = make_offset(offset)
            rapdu,sw1,sw2 = ap.transmit_secure(connection,0x00,0xB0,p1,p2,None,None,[last_len])
            data = ap.parse_decrypt_do87(rapdu)
            data_block += data

            # extract jp2 from dg2 data stream
            self.raw_image = get_raw_image(data_block)

        else:
            raise ValueError("could not read DG2.COM (wrong tag)")

