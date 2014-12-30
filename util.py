from operator import xor

DES_PAD= [0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

def pad(block):
    "add DES padding to data block"
    # call with null string to return an 8 byte padding block
    # call with an unknown sized block to return the block padded to a multiple of 8 bytes
    # first make copy to ensure no unexpected side effect on incoming block
    new_block = []
    for i in range(len(block)):
        new_block.append(block[i])
    for x in range(8 - (len(block) % 8)):
        new_block += [DES_PAD[x]]
    return new_block

def unpad(block):
    rev = list(reversed(block))
    l = 0
    while(rev[l] == 0x00):
        l += 1
    if(rev[l] == 0x80):
        return block[:-(l+1)]
    else:
        return block


def il2hs(il):
    "convert a list of bytes (ints) to a hex string"
    string= ''
    for x in range(len(il)):
        string += '%02x' % il[x]
    return string

def hs2il(s):
    """
    converts a hex string into a list of bytes
    as commonly used by pyscard
    @param s: hex string
    @return: converted byte list
    """
    return list(bytearray(s.decode('hex')))

def set_bit_at(v, index, x):
    """
    Set the index:th bit of v to x, and return the new value.
    lowest index is 1, not 0!
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
    :return: encoded length as list of ints
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
        l = seq[2]
        return (seq[0:2],seq[2:l+2])
    else:
        l = seq[0]
        return (seq[0:1],seq[1:l+1])

def xor_lists(ls_a,ls_b):
    ls = []
    for (a,b) in zip(ls_a,ls_b):
        ls.append(xor(a,b))
    return ls

class Tlv_reader():

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
                    None


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