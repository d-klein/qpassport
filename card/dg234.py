from card.util import get_ber_tlv_len, dec_ber_tlv_len, make_offset
from smartcard.util import toHexString
import tlv

class Bio_info_template:

    def __init__(self):
        self.icao_header_version = None
        self.biometric_type = None
        self.biometric_subtype = None
        self.create_date_time = None
        self.validity_period = None
        self.pid_creator = None
        self.bio_data = None
        self.format_owner = None
        self.format_type = None
        self.jpeg = None
        self.jp2 = None

    def __str__(self):
        s = ""
        if(self.icao_header_version):
            s += "Icao Header Version: "+toHexString(self.icao_header_version)+"\n"
        if(self.biometric_type):
            s += "Biometric Type     : "+toHexString(self.biometric_type)+"\n"
        if(self.biometric_subtype):
            s += "Biometric Subtype  : "+toHexString(self.biometric_subtype)+"\n"
        if(self.create_date_time):
            s += "Creation Date/Time : "+toHexString(self.create_date_time)+"\n"
        if(self.validity_period):
            s += "Validity Period    : "+toHexString(self.validity_period)+"\n"
        if(self.pid_creator):
            s += "PID Creator        : "+toHexString(self.pid_creator)+"\n"
        if(self.format_owner):
            s += "Format Owner       : "+toHexString(self.format_owner)+"\n"
        if(self.format_type):
            s += "Format Type        : "+toHexString(self.format_type)+"\n"
        if(len(s) > 0):
            return s.rstrip()
        else:
            return s

class DG234:
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
    def __init__(self,file_id):
        self.bio_info_templates = []
        self.file_id = file_id

    def __get_jp2_image(self,seq):
        # crude version:
        # seek to start of jp2 image and return
        # sequence until end of biometric data block
        idx = 0
        while(idx < len(seq) - 12):
            if(seq[idx:idx+12] == [0x00,0x00,0x00,0x0C,0x6a,0x50,0x20,0x20,0x0d,0x0a,0x87,0x0a]):
                # we got a jpeg2000
                return seq[idx:]
            idx += 1
        raise ValueError("no jpeg2000 found")

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
        self.__parse_bio_templates(data)

    def __parse_bio_templates(self,byte_list):
        data_all = tlv.extract_value([0x7f,0x61],[],byte_list)
        cnt_inst = tlv.extract_value([0x02],[],data_all)
        if(len(cnt_inst) == 1):
            cnt_inst = cnt_inst[0]
            idx = 3
            for i in xrange(0,cnt_inst):
                bit = Bio_info_template()
                data_i = tlv.extract_value([0x7f,0x60],[],data_all[idx:])
                length, _ = get_ber_tlv_len(data_all[idx:])

                bio_data = None
                try:
                    bio_data = tlv.extract_value([0x5f,0x2e],[[0xa1]],data_i)
                except ValueError:
                    try:
                        bio_data = tlv.extract_value([0x7f,0x2e],[[0xa1]],data_i)
                    except ValueError: pass
                bit.bio_data = bio_data
                if(self.file_id == 0x02):
                    try:
                        bit.jp2 = self.__get_jp2_image(bio_data)
                    except ValueError: pass
                    try:
                        bit.jpeg = self.__get_jpg_image(bio_data)
                    except ValueError: pass

                header = tlv.extract_value([0xa1],[],data_i)
                header_tags = [[0x80],[0x81],[0x82],[0x83],[0x85],[0x86],[0x87],[0x88]]
                try:
                    bit.icao_header_version = tlv.extract_value([0x80],header_tags,header)
                except ValueError: pass
                try:
                    bit.biometric_type = tlv.extract_value([0x81],header_tags,header)
                except ValueError: pass
                try:
                    bit.biometric_subtype = tlv.extract_value([0x82],header_tags,header)
                except ValueError: pass
                try:
                    bit.create_date_time = tlv.extract_value([0x83],header_tags,header)
                except ValueError: pass
                try:
                    bit.pid_creator = tlv.extract_value([0x85],header_tags,header)
                except ValueError: pass
                try:
                    bit.format_owner = tlv.extract_value([0x87],header_tags,header)
                except ValueError: pass
                try:
                    bit.format_type = tlv.extract_value([0x88],header_tags,header)
                except ValueError: pass

                self.bio_info_templates.append(bit)
                idx += length
