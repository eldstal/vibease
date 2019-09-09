#!/usr/bin/env python3

# Parse a bluetooth HCI snoop log from communication with
# a Vibease device, decrypting and printing the identified commands and responses.

import sys
import argparse
import vibease

from btsnoop.btsnoop import *


# Returns (True,payload) if the packet is
# a BLE write request of interest
def is_write(metadata, packet):
  if (type(metadata) != l2c_packet): return False,None
  if (metadata.hci_flag != 2): return False,None

  # ATT opcode is the first byte, and we want 0x52 which is
  # a write command.
  if (packet[0] != 0x52): return False,None

  # The next two bytes are the handle to write to.
  # Strip those and we have the actual payload.
  return True,packet[3:]

# Returns (True,payload) if the packet is
# a BLE update notification of interest
def is_response(metadata, packet):
  if (type(metadata) != l2c_packet): return False,None
  if (metadata.hci_flag != 2): return False,None

  # ATT opcode is the first byte,
  # and we want 0x1b which is a value notification
  if (packet[0] != 0x1b): return False,None

  # The next two bytes are the handle to write to.
  # Strip those and we have the actual payload.
  return True,packet[3:]

# Filter out unneccessary stuff from the dump
# Each entry in the returned list is a tuple of
# (index, r/w, payload)
def filter_packets(snoop_log):
  # As far as we know, only write requests
  # from host to device and value notifications
  # from the device are of any interest.
  packets = []
  idx = 1   # Packet number as shown in wireshark
  for metadata,packet in snoop_log.parsed:
    w,payload = is_write(metadata, packet)
    if (w):
      packets += [ (idx,"w",payload) ]
      continue

    r,payload = is_response(metadata, packet)
    if (r):
      packets += [ (idx,"r",payload) ]
      continue

    idx += 1

  return packets


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument("file", type=str, help="btsnoop HCI log to parse")
  conf = parser.parse_args()

  snoop_log = btsnoop(conf.file)
  if (snoop_log is None):
    print("Unable to load btsnoop log {}".format(conf.file))
    return

  packets = filter_packets(snoop_log)

  # A message assembled from multiple successive packets.
  KEY_RX = vibease.KEY2
  KEY_TX = KEY_RX   # Updated to KEY_HS once it's seen in the communication.

  msg = None

  for idx,direction,packet in packets:
    if (msg is None):
      msg = vibease.Msg()
      msg.direction = direction

    if (direction != msg.direction):
      sys.stderr.write("WARNING: {} packet (index {}) found in the middle of a {} message! Ignored.\n".format(direction, idx, msg.direction))
      sys.stderr.write("  {}\n".format(msg.packets))

      continue

    done,plaintext = msg.add_packet(packet.decode("ascii"), KEY_TX, KEY_RX)

    if (done):
      barr = "[" + " ".join(["0x{:02x}".format(b) for b in msg.plaintext ]) + "]"
      print("{} {} {} {}".format(msg.direction, msg.prefix, msg.plaintext, barr))
      msg = None

      # Detect the key exchange and use the HS key the device provided
      if (plaintext[0:3] == "HS=".encode("ascii")):
        KEY_TX = plaintext[3:-1]  # Key truncation bug in the device
        sys.stderr.write("HS Key identified: {}\n".format(KEY_TX))

if __name__ == "__main__":
  main()
