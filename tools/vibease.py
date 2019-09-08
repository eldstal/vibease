#!/usr/bin/env python3

# Useful functions for vibease communications

import base64


# CryptoHandler has two hard-coded keys (for Descramble)
# and one that comes from the vibrator at runtime called HS
KEY1 = "2iYNPjW9ptZj6L7snPfPWIH5onzQ0V1p".encode("ascii")
KEY2 = "4sRewsha3G54ZqEcjr9Iadexd1sKB8vr".encode("ascii")


# Pass in a byte array cryptext
# and a byte-array for a key
# Returns a string
# This is just a plain xor cipher with an offset by one. No big deal.
def Descramble(cryptext, key):
  plaintext = [ b for b in cryptext ]

  for i in range(len(plaintext)):
    plaintext[i] = (plaintext[i] - 1) ^ key[i % len(key)]

  return bytes(plaintext)


# This is the complementary function, which always uses the third key
# and a byte-array for a key
# Returns a byte array
def Scramble(plaintext, key):
  cryptext = [ b for b in plaintext.encode("ascii") ]

  for i in range(len(cryptext)):
    cryptext[i] = (cryptext[i] ^ key[i % len(key)]) + 1

  return bytes(cryptext)

# Pass in a list of packets received
# Returns (probably) a b64-encoded scrambled payload.
def Defragment(packets):
  b64 = ""
  for p in packets:
    content = p[1:-1]
    b64 += content
    if (p[-1] == "!"):
      break
  return b64

# Pass in a string payload, get a list of strings
# for data packets back
# This is how the app breaks a longer payload up for transmission
# in short BLE packets
def ScrambleAndFragment(payload, key):
  scrambled = Scramble(payload,key).decode("ascii").replace("\n", "")
  n_blocks = int(len(scrambled) / 16)
  if (len(scrambled) % 16 != 0):
    n_blocks += 1

  if (n_blocks == 1):
    # Single packet
    return [ "*" + scrambled + "!" ]

  packets = [ ]
  for b in range(n_blocks):
    chunk = scrambled[b*16:(b+1)*16]
    if (b == 0):
      # First packet
      packets += [ "*" + chunk + ">" ]
    elif (b == n_blocks - 1):
      # Last packet
      packets += [ "<" + chunk + "!" ]
    else:
      # Middle packets
      packets += [ "<" + chunk + ">" ]

  return packets



# A multi-packet message to decrypt
# Keep runing add_packet().
# It returns (True,plaintext) when the message is complete.
class Msg:
  def __init__(self):
    self.plaintext = bytes([])
    self.prefix = ""
    self.packets = []

  def add_packet(self, packet, key_tx, key_rx):
    if (len(self.packets) == 0):
      self.prefix = packet[0]

    self.packets += [ packet ]

    if (packet[-1] == "!"):

      # Pick the proper key
      k = { "$": key_rx,
            "*": key_tx,

            "%": key_rx,    # Not actually scrambled
            "#": key_rx }[self.prefix]

      if (self.prefix != "%"):
        b64 = Defragment(self.packets)
        scrambled = base64.b64decode(b64)
        self.plaintext = Descramble(scrambled, k)

      else:
        # These packets aren't b64-encoded or scrambled
        self.plaintext = Defragment(self.packets)

      return True,self.plaintext

    return False,None



