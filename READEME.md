= YubiKey Simulator

This was built by Sam Stelfox referencing the documentation on the Yubico
website and produces valid OTPs based on it's internal variables. It was
funtionally tested against the Google code projects yubikey-val-server and
yubikey-ksm.

One of the things to note: The 'Generate Random Token' feature will generate a
Token ID between 12-16 characters long. The spec of the YubiKey specifies that
the Token ID can be 0-128 bits in length or 0-16 hexadecimal characters. The
validation server and ksm server linked to above ONLY accept 12 character Token
IDs.

The code has been released under the MIT license, this repository holds a copy
of that in the LICENSE FILE.
