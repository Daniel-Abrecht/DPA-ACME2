#!/usr/bin/env python3

import sys, json, base64, hashlib, argparse, textwrap, time
import dns.update, dns.tsigkeyring, dns.query

def base64url(o):
  if isinstance(o, dict):
    o = json.dumps(o)
  if isinstance(o, str):
    o = o.encode('utf-8')
  return base64.urlsafe_b64encode(o).replace(b"=", b"").decode('utf-8')

def main(argv):
  # Parse arguments
  parser = argparse.ArgumentParser(
    allow_abbrev=False,
    formatter_class=argparse.RawDescriptionHelpFormatter,
    description=textwrap.dedent("""\
      DNS-01 challange solver for DPA-ACME using DNS zone updates. This program
      should be called using DPA-ACME.
    """)
  )
  parser.add_argument("--server", required=True, help="DNS server for DNS zone updates")
  parser.add_argument("--zone", help="optional. Specifies in which dns zone the dns zone update should be made. Per default, the challange domain (_acme-challenge.your.domain) is assumed have it's own zone. A number can be specified if a parent domain of the challange domain is the dns zone to change. Alternatively, the name of the dns zone may be explicitly specified.")
  parser.add_argument("--key", nargs=3, metavar=('KEY_NAME','SECRET','ALGORITHM'), help="optional. The key name, secret and algorithm for the TSIG key which may be used to authenticate the DNS zone updates")
  args = parser.parse_args(argv)

  server = args.server

  update_algo = None
  zone_keyring = None
  if args.key:
    zone_keyring = dns.tsigkeyring.from_text({args.key[0]:args.key[1]})
    update_algo = args.key[2]

  zone = 0
  if args.zone and args.zone.isdigit():
    zone = int(args.zone)

  # Prepare for challange
  challenge = json.loads(sys.stdin.readline())

  if challenge['challenge']['type'] != "dns-01":
    raise Exception("{} only supports dns-01 challanges", sys.args[0])

  domain = challenge['authorization']['identifier']['value']
  token = challenge['challenge']['token']
  thumbprint = challenge['account']['jwk_thumb']
  rr_name = '_acme-challenge.'+domain
  keyauthorization = "{0}.{1}".format(token, thumbprint)
  record = base64url(hashlib.sha256(keyauthorization.encode('utf-8')).digest())
  if isinstance(zone,int):
    zone = '.'.join(rr_name.split('.')[zone:])

  # Perform DNS zone update
  update = dns.update.Update(zone, keyring=zone_keyring, keyalgorithm=update_algo)
  update.replace(rr_name+'.', 0, 'TXT', record)
  try:
    response = dns.query.tcp(update, server, timeout=10)
    if response.rcode() != 0:
      raise Exception(f"DNS zone update failed, response was: {response}")
  except:
    raise Exception(f"DNS zone update failed. server: {server} zone: {zone} record: {rr_name}. IN TXT {record}")

  # Wait to make sure records have time to propagate
  time.sleep(10)

  # Finish challange and wait for confirmation
  answare = json.dumps({"keyAuthorization": keyauthorization})
  sys.stdout.write("ready "+answare+'\n')
  sys.stdout.flush()
  while sys.stdin.read(4 * 1024): pass # wait for EOF

  # Cleanup leftover DNS entries
  # It's not fatal if this fails
  try:
    update = dns.update.Update(zone, keyring=zone_keyring, keyalgorithm=update_algo)
    update.delete(rr_name+'.', 'TXT')
    dns.query.tcp(update, server, timeout=10)
  except:
    traceback.print_exc()

if __name__ == "__main__":
    main(sys.argv[1:])
