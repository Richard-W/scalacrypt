Scalacrypt
==========

Scalacrypt provides advanced cryptographic functions for scala projects. It wraps the
javax.crypto API and provides a few things that are not implemented there in a way
usable for this project.

This project is under heavy development and not suited for production use!!!

To add scalacrypt to your sbt project just add the following line to your build.sbt:

```scala
libraryDependencies += "xyz.wiedenhoeft" %% "scalacrypt" % "0.3.0"
```

You can use the current snapshot by putting the following lines in your build.sbt:

```scala
resolvers += Resolver.sonatypeRepo("snapshots")

libraryDependencies += "xyz.wiedenhoeft" %% "scalacrypt" % "0.4-SNAPSHOT"
```

As the API is subject to heavy changes i recommend you use "sbt doc" to get definitive reference.
Im doing my best to keep the documentation and this README up-to-date but as long as i did not
stabilize the API it might sometimes be a little off.

Symmetric encryption
--------------------

Symmetric encryption in scalacrypt is achieved by combining a BlockCipher, a BlockPadding and a BlockCipherMode trait.
These traits are applied to the BlockCipherSuite class. Different choices of these traits need different abstract methods
defined in the derived class. For instance it is necessary to supply a certain Key to all traits deriving from
BlockCipher and an IV to CBC mode.

Example for constructing a BlockCipherSuite. You have to make sure yourself that the IV is valid.
```scala
val outerKey = Key.generate[SymmetricKey128]
val outerIV = Random.nextBytes(16)
val suite = new BlockCipherSuite[SymmetricKey128] with blockciphers.AES128 with modes.CBC with paddings.PKCS7Padding {
	def key = outerKey
	def iv = outerIV
}
```

There are certain helper functions in the 'suites' package. They automatically validate parameters and return a Try.

```scala
val suite = suites.AES128_CBC_PKCS7Padding(Key.generate[SymmetricKey128], None).get
val iv = suite.iv
val key = suite.key
```

KeyType is a specific child of Key. For AES256 it is SymmetricKey256 for example.
You get the idea. The predefined key classes can be instantiated using the following
methods:

```scala
// Using implicit conversion to MightBuildKeyOp
val specificKey = (0 until 16 map { _.toByte }).toSeq.toKey[SymmetricKey128].get
// If the supplied key is invalid toKey will return a Failure and get will throw. When
// you can't guarantee the validity of the key use pattern matching.


val randomKey = Key.generate[SymmetricKey128]
```

When you define own subclasses of Key you should also define appropriate implicit implementations of CanGenerateKey
and MightBuildKey.

The function returned by encrypt and decrypt is able to encrypt a single block so in the case of AES exactly 16 bytes. If your input is not
exactly divisible by the block size you need padding. The BlockPadding trait transforms an Iterator of byte sequences to an Iterator of
properly padded blocks.

When you have created a suite you can use the encrypt/decrypt method to encrypt/decrypt an Iterator[Seq[Byte]] to an Iterator[Try[Seq[Byte]]].
If the resulting iterator contains a single Failure encryption or decryption must be aborted. There are helper methods for processing a single
Seq[Byte] to a single Try[Seq[Byte]]. These helper methods overload encrypt and decrypt.

Asymmetric encryption
---------------------

Since version 0.4 scalacrypt contains an RSA implementation. You can generate a key just like a symmetric key.
The key type is RSAKey. An RSAKey can be either public or private. Internally there are two types of private keys
which essentially do the same but with different computational efficiency (see Chinese Remainder Theorem).

```scala
val privateKey = Key.generate[RSAKey]
val publicKey = privateKey.publicKey
```

RSA keys can be stored using the output of key.bytes. The resulting sequence of bytes can be restored to a key
using its toKey[RSAKey] method. The binary format used for serializing the keys is specific to scalacrypt and
sadly not compatible with anything. This will most likely change.

There is exactly one cipher suite available for RSA encryption: RSAES\_OAEP which implements message encryption
according to PKCS#1. Usage is equivalent to the symmetric cipher suites except decryption will return a Failure
when the private key is unavailable.

Password hashing
----------------

This library contains the util.PBKDF2Easy object which securely hashes a Seq[Byte] using PBKDF2. The used parameters and the salt are encoded
in the resulting Seq[Byte]. It is safe to save the result to a database.

If you want to use the pure PBKDF2 for other purposes than password hashing you can use khash.PBKDF2 which generates KeyedHash objects.
The data supplied to this KeyedHash is used as the salt.

Contributing
------------

* Bug reports are appreciated as much as actual code contributions. Do not hesitate to report if you encounter a problem.
* All parts of this library MUST never throw exceptions. Functions should return a Try if they might fail. Also if you encounter an exception i consider it a bug and would appreciate if you reported it here.
* The library should be kept extensible. It MUST not be necessary to contribute to this library to implement new algorithms. However if you think an algorithm might be of use for others do not hesitate to merge it.
* This project was born out of necessity. There seems to be no other project in scala providing this functionality and i needed it. I am no cryptography expert but i read a few articles about best practices for encryption. You are welcome to tell me where i am wrong. In fact i will not consider this project stable until a few people who **really** know what they are doing reviewed it.
