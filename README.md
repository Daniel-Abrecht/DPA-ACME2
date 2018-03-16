# DPA-ACME2
A Small ACME v2 client. DPA-ACME2 doesn't implement any challenges by itself.
Just tell it which program it shall use to solve which challenge types for
which identifiers (usually domains). 

## Usage Example
```
./dpa-acme2.py --account-key account.key --csr domain.csr --output certificat.pem -- dns-01 zone-update.py --server localhost
```
This will request a certificate for the domains specified in domain.csr, by solving the
dns-01 challenge using the program at ./challenge_solvers/dns-01/zone-update.py.
The argument --server is specific to the zone-update.py challenge solver, and
specifies that the DNS server to update is running on localhost. All available
Arguments for this challenge solver can be viewed using the command
"./challenge_solvers/dns-01/zone-update.py --help". If everithing goes well,
the certificate will be saved as certificat.pem.

## Software Requirements
This program needs python3 and pyOpenSSL version 16.1.0 or newer. If you want to
use the zone-update.py challenge solver, you'll also need dnspython.

## Usage
```
dpa-acme2.py [-h] --account-key ACCOUNT_KEY --csr CSR --output OUTPUT [--ca CA]
             [--contact CONTACT] -- <challenge solver> [-- <challenge solver> ...]
```

### Required arguments
| Argument | Description |
|----------|-------------|
| --account-key | Path to the account private key |
| --csr | Path to certificate signing request |
| --output | Path where the Certificate is saved at |
| -- &lt;challenge solver&gt; | See sections "challenge solver" for details |

### Optional arguments
| Argument | Description |
|----------|-------------|
| -h, --help | Show the help message |
| --ca | URL to the ACME directory of the certificate authority, default is Let's Encrypts staging endpoint: https://acme-staging-v02.api.letsencrypt.org/directory If you want to use Let's Encrypts production endpoint, it's at: https://acme-v02.api.letsencrypt.org/directory |
| --contact | A contact URI. Usually an E-Mail as mailto URI, like 'mailto:me@example.com' |

## Challenge solver
A challenge solver is a Program that can solve certain types of challenges.

### Usage
After each "--", a challenge solver must be specified. You can specify as many of them as you want, but there must be at least one.
Specify a challenge solver as follows:
```
CHALLENGE_TYPE SOLVER_PROGRAM [--identifier IDENTIFIER] [--identifier-type IDENTIFIER_TYPE]
```
The CHALLENGE_TYPE specifies which challenge the SOLVER_PROGRAM can solve. The SOLVER_PROGRAM specifies
which program to use as challenge solver. You can specify programs using an absolute path, a relative path,
or using it's name. If the program name is used, it should be located in "challenge_solvers/${CHALLENGE_TYPE}/${PROGRAM_NAME}".
There has to be at least one challenge solver for any challenge the CA offers to check the Authorization for each identifier. 
There are a few optional extra argument DPA-ACME2 can use to restrict which challenges it will use for which identifiers. Usually,
a challenge solver program will require some additional arguments, you should check the help text of your challenge solvers for them,
DPA-ACME2 won't check them beforehand. The following optional arguments are used by DPA-ACME2:

| Argument | Description |
|----------|-------------|
| --identifier | The identifier for which this solver shall be used, or any identifier. Usually a domain name |
| --identifier-type | The identifier type. Defaults to "DNS", indicating a domain name. There are no other types of identifiers anyway. |

### DPA-ACME2 Challenge solver protocol
The DPA-ACME2 Challenge solver protocol is designed to be as simple as possible:
 1) The challenge solver must output a helptext if the --help argument is specified.
 2) If there are any unrecognised arguments, it must exit with a non-zero exit code.
 3) If there are any problems, it should write an error message to standard error must exit with a non-zero exit code.
 4) If there are no problems, it should read one line from stdin. It will contain a json object describing the challenge.
 5) It must check if it actually supports the required challenge type and exit with an error otherwise.
 6) After it got the challenge, it must solve the challenge.
 7) After it solved the challenge, it must write "ready" followed by a space followed by the json object to be sent to the challenge url to complete the challenge followed by a newline. The json object mustn't contain any newlines.
 8) The challange solver should read from stdin until it reaches EOF, after which it can safely cleanup everything it did before.
 9) After the challange solver is done with everything, it must exit with exit code 0.

The json object describing the challenge looks as follows (an example from a dns-01 challenge):
```
{
  "challenge": {
    "url": "https://acme-staging-v02.api.letsencrypt.org/acme/challenge/xxxxxxxxxxxxxxxxxxxx/xxxxx",
    "status": "pending",
    "token": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "type": "dns-01"
  },
  "account": {
    "jwk_thumb": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "jwk": {
      "e": "xxxx",
      "kty": "RSA",
      "n": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx..."
    }
  },
  "authorization": {
    "status": "pending",
    "url": "https://acme-staging-v02.api.letsencrypt.org/acme/authz/xxxxxxxxxxxxxxxxxxxxx",
    "identifier": {
      "type": "dns",
      "value": "dpa.li"
    },
    "expires": "2018-02-16T16:39:24Z",
    "wildcard": true
  }
}
```
