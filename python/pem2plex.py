#!/usr/bin/python
# original credit to @lokulin

import sys
import hashlib
from OpenSSL.crypto import *

def main():
  hash = hashlib.sha512()
  hash.update(('plex').encode('utf-8'))
  hash.update((' [ProcessedMachineIdentifier] ').encode('utf-8')) #edit paste your identifier here without spaces
  passphrase = hash.hexdigest()

  with open('e:\c.crt', 'rb') as f:
    c = f.read()

  with open('e:\k.key', 'rb') as f:
    k = f.read()

  key = load_privatekey(FILETYPE_PEM,k)
  cert = load_certificate(FILETYPE_PEM,c)
  p12 = PKCS12()
  p12.set_certificate(cert)
  p12.set_privatekey(key)
  out_file = open("e:\certificate.p12", 'wb' )
  out_file.write( p12.export(passphrase) )
  
  print(passphrase)

if __name__ == '__main__':
  main()

