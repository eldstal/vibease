#!/usr/bin/env python3

#
# testvibease.connector.n (named CryptoHandler)
# has a few crypto-style functions.
# These are them.
import sys
import base64

from vibease import *

# A key captured on my device. It does not change if I restart the app and pair again.
# This key appears to be provided by the vibrator.
# Host writes to UUID 803C3B1F-D300-1120-0530-33A62B7838C9
# with the payload
#  $aGk=!
# The vibrator responds with two packets.
# In my case, they were
#  #fSFwIxA6Oy9VNAJTNS>
#  <ECNixC!
# These are concatenated by the host to the string
#  "fSFwIxA6Oy9VNAJTNSECNixC"
# This string needs to be decoded from base64 and Descramble()'d using KEY2.
# This yields
#  HS=GxJROgt4fnQDVA3
# which is our key!
KEY_HS_RX = "fSFwIxA6Oy9VNAJTNSECNixC"
KEY_HS = "GxJROgt4fnQDVA3".encode("ascii")

# Due to a bug in the scrambler, the last byte of KEY_HS is ignored.
KEY_HS = KEY_HS[:-1]


def parse_packets(packets, key):
  msg = Msg()

  done = False
  plaintext = None

  for p in packets:
    done,plaintext = msg.add_packet(p, KEY_HS, KEY2)
    if (done): break

  return plaintext

stop_vibe_packets = [
  # Should be "Stop vibrating"
  "*eE57Y2RYQgVX!"
]

# Payloads from some data packets sniffed off the BLE connection
vibe_pattern_packets = [
  # These packets all make up a single write, really.
  # "Test vibration", probably.
  # From the code, this should descramble to
  # "1200,2200,3200,4200,5200,6200,7200,8200,9200,0200"
  "*d0t7Y2RWRwVXQ2N3>",
  "<Z3JsTXljgExCB1df>",
  "<fnNlcnhVfmGAWFkN>",
  "<VV9iaXB0eElnY35Y>",
  "<RQ==!"
]


vibe_pattern_cmd = parse_packets(vibe_pattern_packets, KEY_HS)
print("Vibrate pattern : {}".format(vibe_pattern_cmd))

stop_vibe_pattern_cmd = parse_packets(stop_vibe_packets, KEY_HS)
print("Stop vibrate cmd: {}".format(stop_vibe_pattern_cmd))

key_cmd = Descramble(base64.b64decode("aGk="), KEY2)
print("Key exchange cmd: {}".format(key_cmd))

key_hs_scrambled = base64.b64decode(KEY_HS_RX)
key_hs = Descramble(key_hs_scrambled, KEY2)
print("Key exchange response: {}".format(key_hs))
print("Expected HS key: {}".format(KEY_HS))

