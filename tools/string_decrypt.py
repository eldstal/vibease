#!/usr/bin/env python3
#
# The vibease bluetooth test app has its strings obfuscated,
# to be decrypted at runtime by a variety of similar functions
# spread throughout the codebase.
# This script replicates the decryption functions.

# If called with a java file as input, will attempt to find calls to decrypt functions
# and annotate them with the decrypted strings

# If called without parameters, just dumps some known strings

import argparse
import re


def DecryptString(cryptext, key1, key2):
  length = len(cryptext)
  plaintext = [' '] * length
  i = length - 1
  i2 = i
  while (i >= 0):
    i3 = i2 - 1
    plaintext[i2] = chr(ord(cryptext[i2]) ^ ord(key1))
    if (i3 < 0):
      break
    i = i3 - 1
    plaintext[i3] = chr(ord(cryptext[i3]) ^ key2)
    i2 = i
  return "".join(plaintext)


# Found in connector/h.java as g()
# Rename the class to BLEScanHandler and the function to BLEDecryptString
def BLEDecryptString(cryptext):
  return DecryptString(cryptext, '<', 2)

# Found in android/support/v7/cardview/R.java
# Rename the function to RDecryptString
def RDecryptString(cryptext):
  return DecryptString(cryptext, 'r', 18)




def basic_dump():

  ble_crypts = [
    "O]kRC_vUtUvE",
    "VTkO\"LjSlY\"TcO\"Ow_aYqOdInP{\u001caSlRg_vYf\u001cvS\"HjY\"XgJk_g\u0012\b\u001cPYfUpYaHkRe\u0012,\u0012",
    "PYfUpYaHkRe\u0012,\u0012",
    "tcRfOj]iY",
    "&]EW?\u001d",
    "Jk^g]qY,^nIgHmSvTvYqH",
    "---------------------",
    "iVz/\u0004",
    "\u0019",
    "\u001d",
    "\u0011",
    "\u0011",
    "\u001f",
    "\u0002",
    "\u001d",
    "\u001d",
    "\u0000",
    "\u0002",
    "\u001d",

  ]

  for cryptext in ble_crypts:
    print("{}   =>   {}".format(cryptext, BLEDecryptString(cryptext)))



  r_crypts = [
    "Q\u001d|\u0015`\u0013f\u0007~\u0013f\u001b}\u001caS",
    "\"~\u0017s\u0001wRe\u0013{\u0006",
    "Cn@nAnFnGnDnEnJnKnB",
    "A\u0017a\u0001{\u001d|R{\u00162\u0011}\u0002{\u0017vRf\u001d2\u0011~\u001bb\u0010}\u0013`\u0016",
    "\u0013|\u0016`\u001d{\u0016<\u001as\u0000v\u0005s\u0000w\\p\u001eg\u0017f\u001d}\u0006z-~\u0017",
    "!g\u0002b\u001d`\u000620^7",
    "6}\u0017a\u001c5\u00062!g\u0002b\u001d`\u000620^7",
    "G\u0001w\u0000|\u0013\u0017",
    "B\u001a}\u001cw?}\u0016w\u001e",
    "=A$w\u0000a\u001b}\u001c",
    "S\u0002b$w\u0000a\u001b}\u001c",
    "C<C",
    "1}\u001c|\u0017q\u0006{\u001d|?w\u0001a\u0013u\u0017",
    "Q\u001d|\u001cw\u0011f\u001b}\u001cA\u0006s\u0006g\u0001",
    "!w\u0001a\u001b}\u001c[6",
    "X",
    "x",
    "N",
    "L",
    "S",
  ]

  #for cryptext in r_crypts:
  #  print("{}   // \"{}\"".format(cryptext, RDecryptString(cryptext)))





def annotate_file(filename):
  print("Mangling {}".format(filename))
  original = open(filename, "r").read()
  modified = ""
  # Match a function call, group the quoted string inside as "string"
  # Paired with a function to decrypt the string
  FUNC_RE = [
      (re.compile(r"R\.RDecryptString\((?P<quote>['\"])(?P<string>.*?)(?<!\\)(?P=quote)\)"), RDecryptString),
      (re.compile(r"BLEScanHandler\.BLEDecryptString\((?P<quote>['\"])(?P<string>.*?)(?<!\\)(?P=quote)\)"), BLEDecryptString),
      (re.compile(r"h\.g\((?P<quote>['\"])(?P<string>.*?)(?<!\\)(?P=quote)\)"), BLEDecryptString)
  ]
  made_changes = False

  for line in original.split("\n"):
    found = True

    if (re.match("^\s*//", line)):
      # Don't replace in comment lines!
      found = False

    while found:
      found = False
      for EXPR,DECRYPTOR in FUNC_RE:
        match = EXPR.search(line)
        if (match):
          found = True
          made_changes = True
          modified += "// " + line + "\n"

          cryptext = match.group('string')

          # Squeeze the unicode escape sequences
          cryptext = cryptext.encode('utf-8').decode('unicode-escape')

          annotation = "/* \"{}\" */ \"{}\"".format(cryptext, DECRYPTOR(cryptext))
          line = re.sub(EXPR, annotation, line, count=1)
          print(annotation)

    modified += line + "\n"

  # Overwrite the file. There are comments above every modified line with the original line.
  if (True and made_changes):
    with open(filename, "w") as nuked:
      nuked.write(modified)


if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument("file", type=str, nargs="*", help="Java files to modify")
  conf = parser.parse_args()

  if len(conf.file) == 0:
    basic_dump()
  else:
    for f in conf.file:
      annotate_file(f)
