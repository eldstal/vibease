#!/usr/bin/env python3

#
# testvibease.connector.n (named CryptoHandler)
# has a few crypto-style functions.
# These are them.
import sys
import base64


# CryptoHandler has two hard-coded keys (for Descramble)
# and one that comes from the vibrator at runtime called HS
KEY1 = "2iYNPjW9ptZj6L7snPfPWIH5onzQ0V1p".encode("ascii")
KEY2 = "4sRewsha3G54ZqEcjr9Iadexd1sKB8vr".encode("ascii")

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

# Pass in a byte array cryptext
# and a byte-array for a key
# Returns a string
# This is just a plain xor cipher with an offset by one. No big deal.
def Descramble(cryptext, key):
  plaintext = [ b for b in cryptext ]

  for i in range(len(plaintext)):
    plaintext[i] = (plaintext[i] - 1) ^ key[i % len(key)]

  return bytes(plaintext).decode("ascii")




# This is the complementary function, which always uses the third key
# and a byte-array for a key
# Returns a byte array
def Scramble(plaintext, key):
  cryptext = [ b for b in plaintext.encode("ascii") ]

  for i in range(len(cryptext)):
    cryptext[i] = (cryptext[i] ^ key[i % len(key)]) + 1

  return bytes(cryptext)


# Pass in the magic string that was provided by the vibrator
# in response to $aGK=!
# For example, cryptext might be "fSFwIxA6Oy9VNAJTNSECNixC".
def DecodeAndDescramble(cryptext, key):
  decode = base64.b64decode(cryptext)
  descramble = Descramble(decode, key)
  lines = decode.split("\n")
  for l in lines:
    pass



# Pass in a string, get a list of strings for data packets back
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


# Payloads from some data packets sniffed off the BLE connection
payloads = [
  # These packets all make up a single write, really.
  "*d0t7Y2RWRwVXQ2N3>",   # "Test vibration", probably.
  "<Z3JsTXljgExCB1df>",
  "<fnNlcnhVfmGAWFkN>",
  "<VV9iaXB0eElnY35Y>",
  "<RQ==!",
]

b64_possibly = "d0t7Y2RWRwVXQ2N3Z3JsTXljgExCB1dffnNlcnhVfmGAWFkNVV9iaXB0eElnY35YRQ=="
u64 = base64.b64decode(b64_possibly)
print(u64)
print(Descramble(u64, KEY1))
print(Descramble(u64, KEY2))
print(Descramble(u64, KEY_HS))

for p in payloads:
  print(Descramble(p.encode("ascii"), KEY1))
  print(Descramble(p.encode("ascii"), KEY2))
  print(Descramble(p.encode("ascii"), KEY_HS))
  print(Scramble(p, KEY1))
  print(Scramble(p, KEY2))
  print(Scramble(p, KEY_HS))

packets = ScrambleAndFragment("d0t7Y2RWRwVXQ2N3Z3JsTXljgExCB1dffnNlcnhVfmGAWFkNVV9iaXB0eElnY35YRQ==", KEY1)
for p in packets:
  print(p)


key_cmd = Descramble(base64.b64decode("aGk="), KEY1)
print(key_cmd)
key_cmd = Descramble(base64.b64decode("aGk="), KEY2)
print(key_cmd)

key_hs_scrambled = base64.b64decode(KEY_HS_RX)
key_hs = Descramble(key_hs_scrambled, KEY2)
print(key_hs)
print(KEY_HS)
