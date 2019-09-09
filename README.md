# Introduction
The [Vibease](http://vibease.com) is a Bluetooth Low Energy (BLE) connected vibrator.
This is an outline of my attempt to reverse-engineer its communication protocol.



# Vibease vibrator protocol

## Basic Communication
The vibrator exposes two BLE characteristics using the same UUID. One of them has the property `READ` and the other one has the property `WRITE_WITHOUT_RESPONSE`.
From here on, these will be referred to as `cmd_read` and `cmd_write` respectively.

The host is expected to subscribe to notifications on `cmd_read` using the standard BLE mechanism. These notifications are how the vibrator sends data to the host.

Any data sent from the host to the vibrator is simply written to `cmd_write` after an encryption and fragmentation process outlined below.


## UUIDs of note
The following BLE UUIDs are used, and can help identify a BLE device as a vibease.
```
DE3A0001-7100-57EF-9190-F1BE84232730     This is the service that contains 803C3B1F-...
803C3B1F-D300-1120-0530-33A62B7838C9     This is cmd_read and cmd_write on my device
00002902-0000-1000-8000-00805f9b34fb        This is a descriptor under 803C3B1F-...
00002a4d-0000-1000-8000-00805f9b34fb     This is an alternative to 803C3... on some devices

```



## BLE Packet encryption

Packets are encrypted using a basic offset-by-one-and-xor method.


There are two hardcoded keys used:

```python
KEY1 = "2iYNPjW9ptZj6L7snPfPWIH5onzQ0V1p".encode("ascii")
KEY2 = "4sRewsha3G54ZqEcjr9Iadexd1sKB8vr".encode("ascii")
```

There is also a third key, `KEY_HS` which is sent from the vibrator during an initial handshake.

During use, one key is used for each data direction, they will be referred to as `KEY_TX` for messages sent from the host to the vibrator and `KEY_RX` for messages from the vibrator to the host.

In my device, `KEY_TX=KEY_HS` and `KEY_RX=KEY2`.

Messages to be transmitted are passed through `Scramble()` before fragmentation. Received messages are passed through the complementary `Descramble()` after being reassembled.

These are python implementations of these rudimentary crypto functions:

```python
# Pass in a byte-array cryptext received from the device
# and a byte-array for a key, which is the same key that was used to Scramble()
# This is just a plain xor cipher with an offset by one. No big deal.
def Descramble(cryptext, key):
  plaintext = [ b for b in cryptext ]

  for i in range(len(plaintext)):
    plaintext[i] = (plaintext[i] - 1) ^ key[i % len(key)]

  return bytes(plaintext)


# This is the complementary function, used before transmitting messages
# Pass in a string plaintext message
# and a byte-array for a key
# Returns a byte array
def Scramble(plaintext, key):
  cryptext = [ b for b in plaintext.encode("ascii") ]

  for i in range(len(cryptext)):
    cryptext[i] = (cryptext[i] ^ key[i % len(key)]) + 1

  return bytes(cryptext)
```

### Truncation of `KEY_HS`
There is a slight inconsistency when scrambling and descrambling with `KEY_HS`. Instead of using `len(key)` for the modulo, the vibrator uses `len(key-1)` which means the last character of `KEY_HS` is never actually used.

With the python example above, it is sufficient to truncate the very last byte of `KEY_HS` and both `Scramble()` and `Descramble()` should work as expected using all known keys.

For example, if the device sends `HS=ABCDEFGHIJKLMNO` during handshake, simply set `KEY_HS=ABCDEFGHIJKLMN`

This way, the same function can descramble packets transmitted by the host (using the truncated `KEY_HS`) and packets transmitted by the device (using the full `KEY_TX`).



## Base64 encoding
Once scrambled, the payload is encoded using standard Base64 and passed on for fragmentation.




## BLE Packet fragmentation
Payloads are scrambled according to the above, B64-encoded and then fragmented if necessary. A long b64-encoded payload is split into 16-byte chunks which are surrounded with ASCII markers.

With data bytes denoted as  `DDDD...`, here are the known packet formats:

* A single-chunk payload of data (16 bytes or shorter) is transmitted as `*DDDDD!`
  * The first character of this packet is variable. The host uses `$` or `*`. The device uses `#` or `!`.
* A multi-chunk payload:
  * First 16-byte chunk: `*DDDDDDDDDDDDDDDD>`
    * The same prefix rules apply
  * Following 16-byte chunk(s): `<DDDDDDDDDDDDDDDD>`
  * Last chunk: `<DDDDDDD!`

Each chunk is transmitted as a single write to `cmd_write` or received as a single notification on `cmd_read`. They must be received in their proper order, so don't send the next chunk before the first chunk has been sent.

Here is a python implementation of the scrambling and fragmentation employed in vibease.bluetoothtest:

```python
# Pass in a plaintext string, get a list of strings for data packets back
# This is how the app breaks a longer payload up for transmission
# in short BLE packets
def ScrambleAndFragment(payload, key):
  scrambled = Scramble(payload,key).decode("ascii").replace("\n", "")
  encoded = Base64.b64encode(scrambled)

  n_blocks = int(len(encoded) / 16)
  if (len(encoded) % 16 != 0):
    n_blocks += 1

  if (n_blocks == 1):
    # Single packet
    return [ "*" + encoded + "!" ]

  packets = [ ]
  for b in range(n_blocks):
    chunk = encoded[b*16:(b+1)*16]
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
```

Most messages are prepared for transmission this way (scramble, base64, then fragment).

Some interesting BLE dumps are [here](https://github.com/eldstal/vibease/tree/master/dumps).




## Message prefixes
### Host -> Device
`$` appears to signify that the message is scrambled using `KEY_RX` rather than `KEY_TX`.
`*` appears to signify normal commands, scrambled with `KEY_TX`

### Device -> Host
`%` is used for some sort of version packet, which is entirely unscrambled and not b64 encoded
`#` appears to be used for all normal responses, scrambled with `KEY_RX`




## Known commands
(The examples below use my `KEY_HS=GxJROgt4fnQDVA` and will look different on a different setup.)

### Perform Key Exchange
Unscrambled example (bytes): `0x53 0x1B`
Unscrambled example (ASCII): `S<ESCAPE>`
Transmitted packets:
```
$aGK=!
```
Notes: Since the host does not yet have KEY_HS, I've assumed that this message is scrambled using `KEY_RX`. We'll find out once we see KEY_1 used, perhaps those devices expect a different packet.

### Status Query?
Unscrambled example (bytes): `0x20 0x45`
Transmitted packets:
```
$FTc=!
```

Notes:
* Like the other `$` prefixed command, this appears to also be scrambled using `KEY_RX`, even though it is sent right after key exchange finishes. 

My device responds with the following (plaintext bytes): `[0x20 0x45 0x25 0x0e 0x0b 0x50 0x5e 0x62 0x64 0x19 0x56]`



### Vibrate Pattern
Unscrambled example (ASCII): `1200,2200,3200,4200,5200,6200,7200,8200,9200,0200`
Transmitted packets:
```
*d0t7Y2RWRwVXQ2N3>
<Z3JsTXljgExCB1df>
<fnNlcnhVfmGAWFkN>
<VV9iaXB0eElnY35Y>
<RQ==!
```
Notes:
* The first digit is probably intensity while the remaining three could be duration (ms).
* It appears that a valid pattern is anywhere between 3 and 10 steps.
* The "patterns" feature in the vibease app doesn't use this command, it sends timed "Vibrate Fixed" commands instead.
* The actual result of this command is a little unpredictable. In one instance, the above gave me a sawtoothy pattern as
  expected. In every other case it either did nothing or only started a weak static vibration.

### Vibrate Fixed
Unscrambled example (ASCII): `3150,0020`
Transmitted packets:
```
*dUqAY2RYRQdX!
```
Notes: This comes from the manual control in the main Vibease app, which has a 2D touch surface on the axes "speed" and "strength".

### Stop
Unscrambled example (ASCII): `0500,0500`
Transmitted packets:
```
*eE57Y2RYQgVX!
```
Notes: Given the "vibrate fixed" command follows the same format, this is probably "Zero speed, Zero intensity".



## The initial handshake

The following steps are necessary to obtain `KEY_HS`, which appears to be unique to each vibrator:

```
1. Open a GATT connection to the vibease and bond to it.
2. Locate service de3a0001-7100-57ef-9190-f1be84232730
3. Find the characteristic 803C3B1F-D300-1120-0530-33A62B7838C9
   * There are two of them, one with the READ property and one with the
     WRITE_WITHOUT_RESPONSE property. These are cmd_read and cmd_write.
4. Enable change notification on cmd_read, so that you receive messages when the value changes.
5. Perform a write to cmd_write with the payload $aGk=!   (bytes [ 0x24, 0x61, 0x47, 0x6b, 0x3d, 0x21 ])
6. Three notifications come in, in order. In my setup they are:
   #fSFwIxA6Oy9VNAJTNS>
   <ECNixC!
   %1406-OK!
```

The first two are a fragmented single message. Defragment, b64-decode and descramble using `KEY_TX` to get the payload:

```
HS=GxJROgt4fnQDVA3
```

This key will probably be different for different devices. Truncate the very last byte of this key to get the key:

```
KEY_RX=GxJROgt4fnQDVA
```

### Compatibility notes
There is another uuid, `0002a4d-0000-1000-8000-00805f9b34fb` which is used interchangably with `803...` if found. My device does not have this characteristic, but maybe it's for legacy devices or some other product. This might also be the device that uses `KEY1` as its `KEY_TX`.

If you are implementing the device side of this communication, you should probably choose a `KEY_HS` of equal length to the above example, including the extra byte of garbage.

## HELO
After key exchange has been completed, the device sends an unscrambled and un-base64'd message like
```
%1406-OK!
```

which appears to be a version number and a basic status report.


## Status request
The official apps send the `Status Query` command and receive the response right after key exchange has been completed.
