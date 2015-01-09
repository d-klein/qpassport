from card.util import get_ber_tlv_len, dec_ber_tlv_len, make_offset
from smartcard.util import toHexString
import tags
import tlv

class Image_template:

    def __init__(self):
        self.portrait = None
        self.signature = None

class DG567:
    """
    given a pyscard connection and a secure messenger,
    read dg5/6/7 and extract the image file

    Example:
        >>> dg2 = DG2()
        >>> dg2.read(connection, secure_messenger)
        >>> if(dg2.raw_image):
        >>>     img= open("portrait.jp2",'wb+')
        >>>     img.write(bytearray(dg2.raw_image))
        >>>     img.flush()
        >>>     img.close()

    """
    def __init__(self,file_id):
        self.image_templates = []
        self.file_id = file_id

    def __get_jpg_image(self,seq):
        # crude version:
        # seek to start of jpg image and return
        # sequence until end of biometric data block
        idx = 0
        while(idx < len(seq) - 4):
            if(seq[idx:idx+4] == [0xFF,0xD8,0xFF,0xE0]):
                # we got a jpeg/jfif
                return seq[idx:]
            idx += 1
        raise ValueError("no jpeg found")


    def __parse_image_templates(self,byte_list):
        data = byte_list
        instances = 1
        if(byte_list[0] == 0x02):
            # multiple instances
            instances = byte_list[1]
            data = byte_list[2:]
        idx = 0
        for i in xrange(0,instances):
            t = Image_template()
            length, _ = get_ber_tlv_len(data[idx:])
            try:
                img = tlv.extract_value([0x5f,0x40],[[0x5f,0x40],[0x5f,0x43]],data[idx:])
                t.portrait = self.__get_jpg_image(img)
            except ValueError: pass
            try:
                img = tlv.extract_value([0x5f,0x43],[[0x5f,0x40],[0x5f,0x43]],data[idx:])
                t.signature = self.__get_jpg_image(img)
            except ValueError: pass

            idx += length

    def read_dg567(self,connection,ap):
        """
        reads jp2 image from dg2 and stores list of byte
        in self.raw_image

        :param connection: pyscard connection
        :param ap: secure messaging object for apdu protection
        :return:
        """

        # select DG2
        ap.transmit_secure(connection,0x00,0xA4,0x02,0x0C,[0x02],[0x01,self.file_id],None)

        # read length (first 6 bytes) of DG2 to get file length
        rapdu,sw1,sw2 = ap.transmit_secure(connection,0x00,0xB0,0x00,0x00,None,None,[0x06])
        data = ap.parse_decrypt_do87(rapdu)

        if(data[0] == 0x65 or data[0] == 0x67):
            # read DG2/DG3/DG4
            # decode length of DG2/3/4
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

            # extract image templates
            self.__parse_image_templates(data_block)
        else:
            raise ValueError("error reading datagroup (not present?)")