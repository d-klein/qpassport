from operator import xor
from smartcard.util import toHexString

DES_PAD= [0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

def pad(block):
    """
    add DES padding to data block and returns padded data block

    input/output is a list of bytes, such as [0x00,0x01,0x2,...]
    call with empty list to return an 8 byte padding block
    call with an unknown sized block to return the block padded to a multiple of 8 bytes
    modifies calling argument, so first make copy to ensure no unexpected
    side effect!

    :param block: list of bytes, such as [0x00,0x01,0x2,...]
    :return: list of bytes, such as [0x00,0x01,0x2,...]
    """
    new_block = []
    for i in range(len(block)):
        new_block.append(block[i])
    for x in range(8 - (len(block) % 8)):
        new_block += [DES_PAD[x]]
    return new_block

def unpad(block):
    """
    removes padding from a DES padded data block

    :param block: list of bytes such as [0x00,0x01,0x2,...]
    :return: list of bytes such as [0x00,0x01,0x2,...]
    """
    rev = list(reversed(block))
    l = 0
    while(rev[l] == 0x00):
        l += 1
    if(rev[l] == 0x80):
        return block[:-(l+1)]
    else:
        return block


def il2hs(il):
    """
    convert a list of bytes (ints) to a hex string

    :param il: list of bytes (ints) such as [0x00,0x01,0x2,...]
    :return: string with hex chars, such as "000102"
    """
    string= ''
    for x in range(len(il)):
        string += '%02x' % il[x]
    return string

def hs2il(s):
    """
    converts a hex string into a list of bytes (ints)

    :param s: hex string such as "CAFEBABE"
    :return: list of byte (int) such as [0xCA,0xFE,0xBA,0xBE]
    """
    return list(bytearray(s.decode('hex')))

def set_bit_at(v, index, x):
    """
    Set the index:th bit of v to x, and return the new value.
    lowest index is 0

    :param v: byte/int about to be modified
    :param index: bit index of v
    :param x: zero/one or True/False
    :return:
    """
    mask = 1 << index
    v &= ~mask
    if x:
        v |= mask
    return v

def ber_tlv_len(l):
    """
    for given int l returns the minimal length encoding according
    to the modified version von BER-TLV defined in ISO 7816-4

    :param l: length as int
    :return: encoded length as list of bytes
    """
    if(l <= 127):
        return [l]
    elif(l <= 255):
        return [0x81,l]
    elif(l<= 65535):
        return [0x82] + [l/256,l%256]
    elif(l<= 16777215):
        return [0x83] + [l/65536,l/256,l%256]
    elif(l<= 4294967295):
        return [0x84] + [l/16777216, l/65536,l/256,l%256]
    else:
        raise ValueError("ber_tlv_len: length not supported")

def dec_ber_tlv_len(seq):
    """
    given a length-value block as a list of bytes, decodes
    the ISO 7816-4 length encoding to l, and then extracts the
    data block of length l

    Example:
        >>> dec_ber_tlv_len([0x81, 0xFE, 0xCA, ...])
        >>> [0xCA, ... ]

    :param seq: list of bytes (length value sequence)
    :return: tuple: first element is list of length bytes, snd is data block
    """
    l = 0
    if(seq[0] == 0x84):
        l = 16777216 * seq[1] + 65536 * seq[2] + 256*seq[3] + seq[4]
        return (seq[0:5], seq[5:l+5])
    elif(seq[0] == 0x83):
        l = 65536 * seq[1] + 256*seq[2] + seq[3]
        return (seq[0:4],seq[4:l+4])
    elif(seq[0] == 0x82):
        l = 256*seq[1] + seq[2]
        return (seq[0:3],seq[3:l+3])
    elif(seq[0] == 0x81):
        l = seq[1]
        return (seq[0:2],seq[2:l+2])
    else:
        l = seq[0]
        return (seq[0:1],seq[1:l+1])

def get_ber_tlv_len(seq):
    """
    given a length-value block as a list of bytes, decodes
    the ISO 7816-4 length encoding to l and returns l
    and the length of bytes encoding l as a tuple

    Example:
        >>> get_ber_tlv_len([0x81, 0xFE, 0xCA, ...])
        >>> (0xFE, 2)

    :param seq: list of byte
    :return: list of byte
    """
    l = 0
    if(seq[0] == 0x84):
        l = 16777216 * seq[1] + 65536 * seq[2] + 256*seq[3] + seq[4]
        return l,5
    elif(seq[0] == 0x83):
        l = 65536 * seq[1] + 256*seq[2] + seq[3]
        return l,4
    elif(seq[0] == 0x82):
        l = 256*seq[1] + seq[2]
        return l,3
    elif(seq[0] == 0x81):
        l = seq[1]
        return l,2
    else:
        l = seq[0]
        return l,1

def make_offset(int_val):
    """
    for a given integer value <= 65535, returns
    two bytes p1 and p2, such that p1 concatenated with p2
    yields the value. Needed for read binary command (i.e. p1||p2)
    as in ISO 7816-4

    :param int_val: a integer value denoting a length
    :return: a tuple (p1,p2), both integers
    """
    x = int_val // 256
    r = int_val % 256
    return (x,r)

def xor_lists(ls_a,ls_b):
    """
    given two lists [x_1,...,x_n] and [y_1,...,y_n] of same
    length, returns [x_1 xor y_1, ..., x_n xor y_n]
    :param ls_a: list of integers
    :param ls_b: list of integers
    :return: list of integers
    """
    ls = []
    for (a,b) in zip(ls_a,ls_b):
        ls.append(xor(a,b))
    return ls


class Tlv_reader():
    """
    very simple TLV Decoder

    Example:
        initialize with list of tags [0xCA] and byte sequence
        >>> reader = Tlv_reader([[0xCA], [0xFE]], [0xCA, 0x02, 0xAA, 0xBB, 0xFE, 0x01, 0xEF])
        read the data field of tag 0xCA
        >>> reader.read([0xCA])
        [0xAA, 0xBB]

    can only decode TLV sequences where length field has one byte length,
    i.e. value is <= 255 byte
    """
    def __init__(self,tag_list, byte_seq):
        self.tags = tag_list
        self.bytes = byte_seq

    def read(self,tag):
        if(not tag in self.tags):
            raise ValueError("unknown tag: "+toHexString([tag]))
        else:
            found = None
            idx = 0
            while(idx < len(self.bytes) -2):
                if(self.bytes[idx:idx+1] == tag):
                    l = self.bytes[idx+1]
                    return self.bytes[idx+2:idx+2+l]
                elif(self.bytes[idx:idx+2] == tag):
                    l = self.bytes[idx+2]
                    return self.bytes[idx+3:idx+3+l]
                elif(self.bytes[idx:idx+1] in self.tags):
                    l = self.bytes[idx+1]
                    idx = idx + 2 + l
                elif(self.bytes[idx:idx+2] in self.tags):
                    l = self.bytes[idx+2]
                    idx = idx + 3 + l
                else:
                    print("error")
                    None

""" Tests
from smartcard.util import toHexString
seq = hs2il('0104')
print("expected: 04")
x,y = dec_ber_tlv_len(seq)
print("received: "+toHexString(y))
seq = hs2il('09019ff0ec34f99226519020231423')
print("expected: 01 9f f0 ec 34 f9 92 26 51")
x,y = dec_ber_tlv_len(seq)
print("received: "+toHexString(y))
seq = hs2il('60145F0180000000')
print("expected: 60 14 5F 01")
print("unpadded: "+toHexString(unpad(seq)))
seq = hs2il('60145F01')
print("expected: 60 14 5F 01")
print("unpadded: "+toHexString(unpad(seq)))
print("ber tlv of 12704: "+toHexString(ber_tlv_len(12704*1024)))
print("dec ber-tlv of 82319EC: "+str(get_ber_tlv_len([0x082,0x31,0x9E])))
"""