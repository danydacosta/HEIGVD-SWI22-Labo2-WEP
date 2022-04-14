#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message given the WEP key"""

from rc4 import RC4
import binascii
from scapy.all import *
__author__ = "Dany Oliveira da Costa & Stefan Simeunovic"
__copyright__ = "Copyright 2022, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__status__ = "Prototype"


INPUT_CAP_FILENAME = 'arp.cap'
OUTPUT_CAP_FILENAME = 'manual-encrypted.cap'
iface = "en0" # interface à utiliser pour envoyer la trame
transmitter_mac = '2E:65:ED:50:BD:66'

# Message, passphrase et IV repris depuis arp.cap
MESSAGE = b'\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x90\x27\xe4\xea\x61\xf2\xc0\xa8\x01\x64\x00\x00\x00\x00\x00\x00\xc0\xa8\x01\xc8'
PASSPHRASE = b'\xaa\xaa\xaa\xaa\xaa'
IV = b'\x0c\x4d\x5c'

SEED = IV + PASSPHRASE

# ICV = CRC-32 sur MESSAGE
ICV = binascii.crc32(MESSAGE)
# doit être converti en bytes pour être concaténé au MESSAGE
ICV = ICV.to_bytes(4, 'little')

cipher = RC4(SEED, streaming=False)
encrypted_text = cipher.crypt(MESSAGE + ICV)

# Modification de la trame du arp.cap
arp = rdpcap(INPUT_CAP_FILENAME)[0]
arp[2].wepdata = encrypted_text[:-4]  # message chiffré
arp[2].icv = int.from_bytes(
    encrypted_text[-4:], byteorder='big')  # icv chiffré

# Enregistrement dans un nouveau .cap
wrpcap(OUTPUT_CAP_FILENAME, PacketList([arp]), append=False)
print('Manual-encrypted message saved in ' + OUTPUT_CAP_FILENAME)

# Envoyer la trame avec scapy
print('Sending packet...')
sendp(PacketList([arp]), inter=0.1, count=10, iface=iface, verbose=1)