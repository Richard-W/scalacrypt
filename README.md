Scalacrypt
==========

Scalacrypt provides advanced cryptographic functions for scala projects. It wraps the
javax.crypto API and provides a few things that are not implemented there. So far
this project only provides symmetric encryption. This may change in the future.

This project is under heavy development and not suited for production!!!

Symmetric encryption
--------------------

Every algorithm that encrypts symmetrically extends the SymmetricEncryption trait. This
trait contains the following abstract methods:

```scala
/** Encrypts data with a given key. */
def encrypt(data: Seq[Byte], key: KeyType): Seq[Byte]

/** Decrypts data using a given key. */
def decrypt(data: Seq[Byte], key: KeyType): Try[Seq[Byte]]
```

KeyType is a specific child of SymmetricKey. For AES256 it is SymmetricKey256 for example.
You get the idea.

For secure encryption a pure SymmetricEncryption should never be used as an attacker would
be able to flip any byte he wishes. For this purpose there is the CipherSuite class which
signs the output of an encryption algorithm using a MAC. It extends SymmetricEncryption too,
so usage is the same.

Binary format
-------------

The AES implementations use cipher block chaining mode (CBC) which randomizes the output
independent of the plaintext. The IV is prepended to the encrypted data (the first 16 bytes).

The CipherSuite class signs the encrypted data and prepends it. The offset depends on the
length of the specific Mac.
