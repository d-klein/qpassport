from util import get_ber_tlv_len
from util import make_offset
from smartcard.util import toHexString

def read_unencrypted(con,file_id):
    # select file
    rapdu, sw1, sw2 = con.transmit([0x00,0xA4,0x02,0x0C,0x02,0x01,file_id])

    # read first 6 byte to get length
    rdata1,sw1,sw2 = con.transmit([0x00,0xB0,0x00,0x00,0x06])
    print("rdata: "+toHexString(rdata1))

    # read file by iterating
    l,len_of_l = get_ber_tlv_len(rdata1[1:])
    print("len: "+str(l))
    data_block = []
    # offset = 1 for tag byte + length of length field itself
    offset = len_of_l + 1
    iterations = l // 255
    last_len = l % 255
    # read data group content
    for i in xrange(0,iterations):
        p1,p2 = make_offset(offset)
        data,sw1,sw2 = con.transmit([0x00,0xB0,p1,p2,255])
        data_block.extend(data)
        offset += 255
    p1,p2 = make_offset(offset)
    data,sw1,sw2 = con.transmit([0x00,0xB0,p1,p2,last_len])
    data_block += rdata1[0:3] + data

    return data_block

def read_secure(sm, con,tag,file_id):
    """

    :param sm: secure_messaging.Secure_Messenger object
    :param con: smartcard.connection object
    :param tag: byte containing file tag
    :param file_id: byte with short file id
    :return: read data block of file
    """

    # select DG2
    sm.transmit_secure(con,0x00,0xA4,0x02,0x0C,[0x02],[0x01,file_id],None)

    # read length (first 6 bytes) of DG to get file length
    rapdu,sw1,sw2 = sm.transmit_secure(con,0x00,0xB0,0x00,0x00,None,None,[0x06])
    data = sm.parse_decrypt_do87(rapdu)

    if(data[0] == tag):
        # decode file length
        l,len_of_l = get_ber_tlv_len(data[1:])
        data_block = []
        # offset = 1 for tag byte + length of length field itself
        offset = len_of_l + 1
        iterations = l // 255
        last_len = l % 255
        # read data group content
        for i in xrange(0,iterations):
            p1,p2 = make_offset(offset)
            rapdu,sw1,sw2 = sm.transmit_secure(con,0x00,0xB0,p1,p2,None,None,[255])
            data = sm.parse_decrypt_do87(rapdu)
            data_block.extend(data)
            offset += 255
        p1,p2 = make_offset(offset)
        rapdu,sw1,sw2 = sm.transmit_secure(con,0x00,0xB0,p1,p2,None,None,[last_len])
        data = sm.parse_decrypt_do87(rapdu)
        data_block += data

        return data_block
    else:
        raise ValueError("error reading datagroup (tag not found)")