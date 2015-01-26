from card.util import get_ber_tlv_len, make_offset, Tlv_reader

class DG1:
    """
    given a pyscard connection and a secure messenger,
    read dg1 and extract the machine readable zone (mrz)

    Example:
        >>> dg1 = DG1()
        >>> dg1.read(connection, secure_messenger)
        >>> print("raw byte sequence "+str(dg1.mrz_bin))
        >>> print("mrz line 1: "+str(dg1.mrz_line1))
        >>> print("mrz line 2: "+str(dg1.mrz_line2))
        >>> print("mrz line 3: "+str(dg1.mrz_line3))
    """

    def __init__(self):
        self.mrz_bin = None
        self.mrz_line1 = None
        self.mrz_line2 = None
        self.mrz_line3 = None

    def __str__(self):
        out = ""
        if(self.mrz_line1):
            out += self.mrz_line1
        if(self.mrz_line2):
            out += "\n"+self.mrz_line2
        if(self.mrz_line3):
            out += "\n"+self.mrz_line3
        return out

    def from_bin_data(self,data):
        tlv = Tlv_reader([[0x5F,0x1F]],data)
        self.mrz_bin = tlv.read([0x5F,0x1F])
        mrz_txt = ''.join([chr(x) for x in self.mrz_bin])
        if(len(mrz_txt) == 90):
            # document is td1 (i.e. id-card): 3 lines of 30 char each
            self.mrz_line1 = mrz_txt[0:30]
            self.mrz_line2 = mrz_txt[30:60]
            self.mrz_line3 = mrz_txt[60:90]
        elif(len(mrz_txt) == 72):
            # a visa (two lines of 36)
            self.mrz_line1 = mrz_txt[0:36]
            self.mrz_line2 = mrz_txt[36:72]
        elif(len(mrz_txt) == 88):
            # passport (two lines of 44)
            self.mrz_line1 = mrz_txt[0:44]
            self.mrz_line2 = mrz_txt[44:88]
        else:
            l = len(mrz_txt)
            raise ValueError("unknown MRZ of length "+str(l)+": "+str(mrz_txt))
