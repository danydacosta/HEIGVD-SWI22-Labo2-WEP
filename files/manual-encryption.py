#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message given the WEP key"""

__author__      = "Dany Oliveira da Costa & Stefan Simeunovic"
__copyright__   = "Copyright 2022, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__status__ 		= "Prototype"

from scapy.all import *
import binascii
from rc4 import RC4

# Message, passphrase et IV repris depuis arp.cap
MESSAGE=b'\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x90\x27\xe4\xea\x61\xf2\xc0\xa8\x01\x64\x00\x00\x00\x00\x00\x00\xc0\xa8\x01\xc8'
PASSPHRASE=b'\xaa\xaa\xaa\xaa\xaa'
IV=b'\x0c\x4d\x5c'

SEED=IV + PASSPHRASE

# ICV = CRC-32 sur MESSAGE
ICV = binascii.crc32(MESSAGE)
ICV = ICV.to_bytes(4, 'little') # doit être converti en bytes pour être concaténé au MESSAGE

cipher = RC4(SEED, streaming=False)
encrypted_text=cipher.crypt(MESSAGE + ICV)

# Modification de la trame du arp.cap
arp = rdpcap('arp.cap')[0]
arp[2].wepdata = encrypted_text[:-4] # message chiffré
arp[2].icv = int.from_bytes(encrypted_text[-4:], byteorder='big') # icv chiffré

# Enregistrement dans un nouveau .cap
wrpcap('newArp.cap', PacketList([arp]), append=False)