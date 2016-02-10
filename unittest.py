import logging
import sys
import email
import blam

rootlogger = logging.getLogger('/Blam')
rootlogger.setLevel(logging.DEBUG)

fm = logging.Formatter(fmt='%(asctime)-8s %(levelname)-.1s  %(message)s', datefmt='%H:%M:%S')
ch = logging.StreamHandler()
ch.setFormatter(fm)
rootlogger.addHandler(ch)

B = blam.BlamMilter(unittest=True)
B.client_address = '209.85.218.49'
B.helo = 'mail-oi0-f49.google.com'

with open(sys.argv[1], 'rb') as f:
  raw_eml = f.read()
  eml = email.message_from_bytes(raw_eml)

for lhs,rhs in eml.items():
    B.OnHeader('',lhs,rhs)

_ = raw_eml.split(b'\n\n',1)

B.payload += b'\r\n' + _[1]

B.OnEndBody('')
