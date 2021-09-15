# -*- coding: utf-8 -*-

from werkzeug.security import generate_password_hash, check_password_hash
import string
import random

def generate_password(len_rand=5):
    """generate password randomly
    param: len_rand: length of password
    return: password (include uppercase lowercase and number)
    """
    chr=string.ascii_uppercase+string.ascii_lowercase+string.digits
    for c in "CcIKklOoPpWwXxYy":
        chr=chr.replace(c,"")
    res=''.join(random.choices(chr, k=len_rand))
    return res

def encrypt_password(password= "password",salt_length=128,len_rand=8):
    """encrypt password by sha256 function
    param: password: original password
    param: salt_length: length of output
    param: len_rand: length of random string for concat to password
    return: output of encryption,random string
    """
    
    chr=string.ascii_uppercase+string.ascii_lowercase+string.digits
    rand_str=''.join(random.choices(chr, k=len_rand))
    res=generate_password_hash(password+rand_str,salt_length=salt_length)
    return res,rand_str

def check_password(password_encrypt,password_org,rand_str):
    """check password and hash
    param: password_org: original password
    param: password_encrypt: hash of password
    param: rand_str: random string for concat to password_org
    return: True, if it is correct password, else False
    """
    return check_password_hash(password_encrypt,password_org+rand_str)

password_org=generate_password(len_rand=5)
print(password_org)
hash,rand_str=encrypt_password(password= password_org, salt_length=40,len_rand=8)
print(hash)
check=check_password(hash,password_org,rand_str)
print(check)