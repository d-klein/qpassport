import hashlib

from card.util import hs2il


C_ENC = [0x00, 0x00, 0x00, 0x01]
C_MAC = [0x00, 0x00, 0x00, 0x02]

def toggle_lsb(v):
    """
    flips the LSB in a byte

    :param v: input byte supplied as int
    :return:byte w/ flipped lsb supplied as int
    """
    lsb = v & 1 
    if(lsb):
        v = v & ~1
    else:
        v = v | 1
    return v

def adjust_parity(key):
    """
    adjusts the parity bits of a DES key
    (i.e. flips the bits as spec. in DES)

    :param key: 8 byte DES key as byte list
    :return: adjusted key as byte list
    """
    new_key = []
    for byte in key:
        # convert byte to string of form '010101'
        s = ''
        if(byte<=1):
            s = str(byte)
        else:
            s = bin(byte>>1) + str(byte&1)
        # count number of occ of 1
        occ = s.count('1')  
        if(occ%2 == 0):
            new_key.append(toggle_lsb(byte))
        else:
            new_key.append(byte)
    return new_key

def derive_key(seed,c):
    """
    derives k_a, k_b as specified in ICAO 9303 App 6.1

    :param seed: 16 byte key seed
    :param c: key/mac conc. (see 9303)
    :return : derived 16 byte key
    """
    d = seed + c
    h = hs2il(hashlib.sha1(bytearray(d)).hexdigest())
    k_a = h[:8]
    k_b = h[8:16]
    return(adjust_parity(k_a)+adjust_parity(k_b))

def derive_doc_acc_keys(mrz_info):
    """
    derives the document access keys (K_enc and K_mac)
    for BAC as spec. in ICAO 9303
    :param mrz_info : String constructed from MRZ with
    :return: tuple of k_enc and k_mac, both byte lists
    """
    h_sha1 = hs2il(hashlib.sha1(bytearray(mrz_info)).hexdigest())
    k_seed = h_sha1[:16]
    return (derive_key(k_seed,C_ENC),derive_key(k_seed,C_MAC))

"""
# some tests
# key derivation
k_seed = hs2il('239AB9CB282DAF66231DC5A4DF6BFBAE')
print("expected: AB 94 FD EC F2 67 4F DF B9 B3 91 F8 5D 7F 76 F2")
k_ab = derive_key(k_seed,C_ENC)
print("result  : "+toHexString(k_ab))
print("expected: 79 62 D9 EC E0 3D 1A CD 4C 76 08 9D CE 13 15 43")
k_ab = derive_key(k_seed,C_MAC)
print("result  : "+toHexString(k_ab))

# document access keys
mrz = 'L898902C<369080619406236'
k_enc, k_mac = derive_doc_acc_keys(mrz)
print("expcted: K_enc: AB 94 FD EC F2 67 4F DF B9 B3 91 F8 5D 7F 76 F2")
print("k_enc         : "+toHexString(k_enc))
print("expected K_mac: 79 62 D9 EC E0 3D 1A CD 4C 76 08 9D CE 13 15 43")
print("         k_mac: "+toHexString(k_mac))
"""
