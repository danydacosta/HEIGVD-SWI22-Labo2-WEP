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
OUTPUT_CAP_FILENAME = 'manual-encrypted-fragmented.cap'
iface = "en0" # interface à utiliser pour envoyer la trame
transmitter_mac = '2E:65:ED:50:BD:66'

# Message, passphrase et IV repris depuis arp.cap
messages = [b'\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00', b'\x06\x04\x00\x01\x90\x27\xe4\xea\x61\xf2\xc0\xa8', b'\x01\x64\x00\x00\x00\x00\x00\x00\xc0\xa8\x01\xc8']
PASSPHRASE = b'\xaa\xaa\xaa\xaa\xaa'
IV = b'\x0c\x4d\x5c'

# ICV = CRC-32 sur MESSAGE
icvs = []
for message in messages:
    icvs.append(binascii.crc32(message).to_bytes(4, 'little'))

# seed = IV + passphrase
seeds = []
for i in range(len(messages)):
    # seeds.append(i.to_bytes(3, 'big') + PASSPHRASE) # on incrément l'IV à chaque fragment
    seeds.append(IV + PASSPHRASE)

encrypted_messages = []

for i in range(len(messages)):
    cipher = RC4(seeds[i], streaming=False)
    encrypted_messages.append(cipher.crypt(messages[i] + icvs[i]))

# Modification de la trame du arp.cap
packets = []

for i in range(len(messages)):
    arp = rdpcap(INPUT_CAP_FILENAME)[0]
    arp[1].SC = i # compteur de fragments
    arp[2].wepdata = encrypted_messages[i][:-4]  # message chiffré
    arp[2].icv = int.from_bytes(
        encrypted_messages[i][-4:], byteorder='big')  # icv chiffré

    print('ICV no ' + str(i) + ' : ' + '{:x}'.format(arp[2].icv))

    if i != len(messages) - 1 : # pas le dernier fragment, flag more fragment à 1
        arp[1].FCfield = 0x45

    packets.append(arp)

print(packets)
# Enregistrement dans un nouveau .cap
wrpcap(OUTPUT_CAP_FILENAME, PacketList(packets), append=False)
print('Manual-encrypted fragmented messages saved in ' + OUTPUT_CAP_FILENAME)

# # Envoyer la trame avec scapy
# print('Sending packet...')
# sendp(PacketList([arp]), inter=0.1, count=10, iface=iface, verbose=1)