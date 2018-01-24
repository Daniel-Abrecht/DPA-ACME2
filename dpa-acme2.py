#!/usr/bin/env python3

import re, sys, json, base64, copy, os, errno, subprocess, hashlib, time, argparse, textwrap
from OpenSSL import crypto
from urllib.request import urlopen
from urllib.error import URLError

defaults = {
  "CA": "https://acme-staging-v02.api.letsencrypt.org/directory"
}

moddir = os.path.abspath(os.path.dirname(sys.argv[0]) or '.')

def base64url(o):
  if isinstance(o, dict):
    o = json.dumps(o)
  if isinstance(o, str):
    o = o.encode('utf-8')
  return base64.urlsafe_b64encode(o).replace(b"=", b"").decode('utf-8')

def JWK_Thumbprint(jwk):
  sjwk = json.dumps(
    { 'e': jwk['e'], 'kty': jwk['kty'], 'n': jwk['n'] },
    sort_keys=True, separators=(',', ':')
  )
  return base64url(hashlib.sha256(sjwk.encode('utf-8')).digest())

def int_to_bytes(x):
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

class ChallengeSolver:
  def __init__(self, ctype, exe, args=[], id_val=None, id_type='dns'):
    self.ctype = ctype
    self.args = args
    self.id_val = id_val
    self.id_type = id_type
    if exe.find('/') == -1:
      exe = os.path.join(moddir, 'challenge_solvers', ctype or 'any', exe)
    self.exe = os.path.abspath(exe)
    if not os.access(self.exe, os.X_OK):
      raise OSError(errno.EPERM,'File "{}" isn\'t executable'.format(self.exe))

  def solve(self, challenge, completition_func):
    args = [self.exe] + self.args
    proc = subprocess.Popen(args,stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    proc.stdin.write((json.dumps(challenge)+'\n').encode('utf-8'))
    proc.stdin.flush()
    line = proc.stdout.readline().decode('utf-8')
    if line[:6] != 'ready ':
      raise Exception("Challenge solver failed")
    proc.stdout.close()
    update = json.loads(line[6:])
    try:
      completition_func(challenge, update)
    finally:
      proc.stdin.close()
    if proc.wait() != 0:
      print("Process exited with non-zero exit code {}".format(args))

class ACME2:
  def __init__(self, CA, account_key):
    self.CA = CA
    self.account_key = crypto.load_privatekey(crypto.FILETYPE_PEM, account_key)
    ac_pub_numbers = self.account_key.to_cryptography_key().public_key().public_numbers()
    self.jws_jwk = {
      "kty": "RSA",
      "e": base64url(int_to_bytes(ac_pub_numbers.e)),
      "n": base64url(int_to_bytes(ac_pub_numbers.n))
    }
    self.nonce = None
    self.account = None
    self.account_url = None
    self.contact = []
    self.directory = json.loads(self.request(CA)[0])

  def request(self, url, payload=None):
    if isinstance(payload, str):
      payload = payload.encode('utf-8')
    response = urlopen(url, payload)
    if 'Replay-Nonce' in response.headers:
      self.nonce = response.headers['Replay-Nonce']
    return response.read().decode("utf-8"), response.status, response.headers

  def newNonce(self):
    self.nonce = urlopen(self.directory['newNonce']).headers['Replay-Nonce']

  def requestJWS(self, url, payload):
    if not self.nonce:
      self.newNonce()
    protected = {
      "alg": "RS256",
      "url": url
    }
    if url in [self.directory['newAccount'],self.directory['revokeCert']]:
      protected["jwk"] = self.jws_jwk
    else:
      self.createAccount()
      protected['kid'] = self.account_url
    protected["nonce"] = self.nonce
    request = {
      "protected": base64url(protected),
      "payload": base64url(payload)
    }
    request['signature'] = base64url(crypto.sign(self.account_key, request['protected'] + '.' + request['payload'], 'sha256'))
    return self.request(url, json.dumps(request))

  def createAccount(self):
    if not self.account_url:
      payload = {"termsOfServiceAgreed": True}
      if len(self.contact):
        payload["contact"] = self.contact
      account, status, headers = self.requestJWS(self.directory['newAccount'], payload)
      self.account_url = headers['Location']
      if account.strip(): # This should always happen
        self.account = json.loads(account)
      else: # But if not, we need to get it from the returned location field :(
        self.account = json.loads(self.requestJWS(self.account_url,payload)[0])
    return self.account

  def makeOrder(self, domains):
    payload = {
      'identifiers': [ {'type':'dns', 'value': domain} for domain in domains ]
    }
    return json.loads(self.requestJWS(self.directory['newOrder'],payload)[0])

  def getAuthorization(self,url):
    auth = json.loads(self.request(url)[0])
    auth['url'] = url
    return auth

  def resolveChallenges(self, authorizations, challengeSolvers):
    challengeSolvers = sorted( challengeSolvers,
      key = lambda x: (x.id_val is None)*4 + (x.ctype is None)*2 + (x.id_type is None)
    )
    challenges = []
    for authorization in authorizations:
      if authorization['status'] == 'valid':
        continue
      aauth = copy.deepcopy(authorization)
      chs = aauth['challenges']
      del aauth['challenges']
      def findMatch():
        for solver in challengeSolvers:
          for ch in chs:
            if ( ( solver.id_val is None or aauth['identifier']['value'] == solver.id_val )
             and ( solver.id_type is None or aauth['identifier']['type'] == solver.id_type )
             and ( solver.ctype is None or ch['type'] == solver.ctype )
            ): return ( solver, {
              "authorization": aauth,
              "challenge": ch,
              "account": {'jwk':self.jws_jwk, "jwk_thumb": JWK_Thumbprint(self.jws_jwk)}
            })
        raise Exception("No solver for any challenge of authorization found: {}".format(authorization))
      challenges += [findMatch()]
    for challenge in challenges:
      challenge[0].solve(challenge[1],self.completeChallenge)

  def completeChallenge(self, challenge, update):
    url = challenge['challenge']['url']
    challenge_result = json.loads(self.requestJWS(url,update)[0])
    attemps = 10
    while ( challenge_result['status'] in ['pending','processing'] ) and 0<--attemps:
      time.sleep(1)
      challenge_result = json.loads(self.request(url)[0])
    if not attemps:
      raise Exception("Timeout, challenge still pending or processing after about 10 seconds")
    if challenge_result['status'] == 'invalid':
      raise Exception('Challenge failed: '+challenge_result['error']['detail'])
    if challenge_result['status'] != 'valid':
      raise Exception('Unexpected challenge status: '+challenge_result['status'])

  def finalizeOrder(self, order, scsr):
    csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, scsr)
    der = crypto.dump_certificate_request(crypto.FILETYPE_ASN1,csr)
    self.requestJWS(order['finalize'], {'csr': base64url(der)})

  def getCertificat(self, scsr, challengeSolvers):
    csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, scsr)
    domains = [x[1].decode('utf-8') for x in csr.get_subject().get_components() if x[0] == b'CN']
    order = self.makeOrder(domains)
    if order['status'] == 'pending':
      authorizations = [ self.getAuthorization(url) for url in order['authorizations'] ]
      self.resolveChallenges(authorizations, challengeSolvers)
      self.finalizeOrder(order, scsr)
    elif order['status'] != 'valid':
      raise ValueError("Unexpected order status: "+order['status'])
    return self.request(order['certificate']) # WTF! No authentication to get the certificate!?!


def main(argv):

  arg_parts = []
  arg_part = []
  for arg in argv:
    if arg == '--':
      arg_parts += [arg_part]
      arg_part = []
    else:
      arg_part += [arg]
  arg_parts += [arg_part]
  del arg_part

  solver_parser = argparse.ArgumentParser( allow_abbrev=False, prog='CHALLENGE_TYPE SOLVER_PROGRAM' )
  solver_parser.add_argument("--identifier", help="The Identifier for which this solver shall be used, or any identifier. Usually a domain name.")
  solver_parser.add_argument("--identifier-type", default="dns", help="The Identifier type. Usually a domain name.")

  parser = argparse.ArgumentParser(
    allow_abbrev = False,
    epilog = '<challenge solver> ' + solver_parser.format_help(),
    formatter_class = argparse.RawDescriptionHelpFormatter,
    description = textwrap.dedent("""\
      Small ACME v2 client. DPA-ACME2 doesn't implement any challenges by itself.
      Just tell it which program it shall use to solve which challenge types for
      which identifiers (usually domains). You can specify programs using an
      absolute path, a relative path, or using it's name. If the program name is
      used, it should be located in "challenge_solvers/${CHALLENGE_TYPE}/${PROGRAM_NAME}"
    """)
  )
  parser.add_argument("--account-key", required=True, help="path to account private key")
  parser.add_argument("--csr", required=True, help="path to certificate signing request")
  parser.add_argument("--output", required=True, help="Where shall the certificate be written to?")
  parser.add_argument("--ca", default=defaults['CA'], help="URL to ACME directory of certificate authority, default is Let's Encrypt")
  parser.add_argument("--contact", action='append', help="A contact URI. Usually an E-Mail as mailto URI, like 'mailto:me@example.com'")

  parser.usage = '\n       '.join(textwrap.wrap(' '.join(parser.format_usage().split())[7:] + ' -- <challenge solver> [-- <challenge solver> ...]\n'))

  args = parser.parse_args(arg_parts.pop(0))

  if len(arg_parts) < 1 or True in [len(x)<2 for x in arg_parts]:
    parser.print_help()
    exit(2)

  solvers = []
  for params in arg_parts:
    ctype = params.pop(0)
    exe = params.pop(0)
    sargs, remaining = solver_parser.parse_known_args(params)
    solvers += [ChallengeSolver(ctype, exe, args=remaining, id_type=sargs.identifier_type, id_val=sargs.identifier)]

  with open(args.account_key,'rb') as key:
    acme = ACME2(args.ca, key.read())
  acme.contact = args.contact or []
  with open(args.csr,'rb') as csr:
    certificate = acme.getCertificat(csr.read(), solvers)
  with open(args.output,'wb') as output:
    output.write(certificate)

if __name__ == "__main__":
  try:
    main(sys.argv[1:])
  except URLError as e:
    print(e.code,e.msg)
    print(e.headers)
    print(e.fp.read())
    raise
