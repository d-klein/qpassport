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

    def from_bin_data(self,data):
        self.__parse_image_templates(data)

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

