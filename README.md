Please find here a go wrapper to the IBM ep11 library used to execute cryptographic operation on IBM Hardware Security Module (IBM Crypto Express cards CX8S, CX7S)

The library focus on Digital Assets related cryptography schema and elliptic curves : EcDsa, Slip10 and EIP2333 derivations, BLS12-381, ED25519, Secp256k1.

Fips Sessions, Master Key rotation (see reencipher samples) are supported.

Prerequisites:
   - IBM LinuxONE or IBM zSystems server using IBM Crypto Express cards.
   - ep11 libraries packages installed
   - Go 1.24+ tested

The master key on the HSM must be loaded and active.
