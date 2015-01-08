from util import get_ber_tlv_len, dec_ber_tlv_len
from smartcard.util import toHexString

# only flat structure
# tag and elements of tags must be a lists
# containing one or two bytes

def extract_value(tag,known_tags,byte_list):
    idx = 0
    l_bl = len(byte_list)
    # check for one byte
    while(idx < l_bl):
        # check for one byte tag
        if(idx < l_bl - 3):
            # at least one byte each for TLV
            tag_idx = [byte_list[idx]]
            if(tag_idx == tag):
                # extract tag and return
                _, seq = dec_ber_tlv_len(byte_list[idx+1:])
                return seq
            elif(tag_idx in known_tags):
                # skip that tag
                tag_len, len_len = get_ber_tlv_len(byte_list[idx+1:])
                idx += tag_len + len_len + 1
            # check for two byte tag
            elif(idx < l_bl - 4):
                # at least two byte for T, and one each for LV
                tag_idx = byte_list[idx:idx+2]
                if(tag_idx == tag):
                    _ , seq = dec_ber_tlv_len(byte_list[idx+2:])
                    return seq
                elif(tag_idx in known_tags):
                    # skip that tag
                    tag_len, _ = get_ber_tlv_len(byte_list[idx+2:])
                    idx += tag_len
                # tag is unknown; this cannot be parsed since
                # we do not know whether:
                # a) uknown tag is one byte, next byte is length
                # b) unknown tag is two bytes, third byte is length
                # etc.
                else:
                    raise ValueError("unknown tag: "+toHexString(tag))
        else:
            raise ValueError("tag "+toHexString(tag)+" not found")