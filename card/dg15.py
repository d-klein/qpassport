from smartcard.util import toHexString
from asn1tinydecoder import *

class DG15:

    def __init__(self):
        self.oid = None
        self.subjectPublicKey = None
        self.modulus = None
        self.publicExponent = None
        
    def __str__(self):
        out = ""
        if(self.oid):
            out += "Algorithm OID:\n"+toHexString(self.oid)
        if(self.subjectPublicKey):
            out += "\nPublic Key:\n"+toHexString(self.subjectPublicKey)
        if(self.modulus):
            out += "\nmodulus:\n"+toHexString(self.modulus)
        if(self.publicExponent):
            out += "\npublic exponent:\n"+toHexString(self.publicExponent)
        return out

    def from_bin_data(self,data):
        self.__parse_subjecPublicKeyInfo(data);
            
    def __parse_subjecPublicKeyInfo(self,byte_list):
        
        root = asn1_node_root(byte_list)
        algorithm = asn1_node_first_child(byte_list, root)
        algorithm_oid = asn1_node_first_child(byte_list, algorithm)
        self.oid = asn1_get_value_of_type(byte_list, algorithm_oid, 'OBJECT IDENTIFIER')
        
        rsaPubKey = asn1_node_next(byte_list, algorithm)
        self.subjectPublicKey = bitstr_to_bytestr(asn1_get_value_of_type(byte_list, rsaPubKey, 'BIT STRING'))
        
        root = asn1_node_root(self.subjectPublicKey)
        firstchild = asn1_node_first_child(self.subjectPublicKey, root)
        self.modulus = asn1_get_value_of_type(self.subjectPublicKey, firstchild, 'INTEGER')
        
        secondchild = asn1_node_next(self.subjectPublicKey, firstchild)
        self.publicExponent = asn1_get_value_of_type(self.subjectPublicKey, secondchild, 'INTEGER')

