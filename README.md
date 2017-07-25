Scalacrypt
==========

[![Build Status](https://travis-ci.org/Richard-W/scalacrypt.svg?branch=master)](https://travis-ci.org/Richard-W/scalacrypt)
[![Coverage Status](https://coveralls.io/repos/Richard-W/scalacrypt/badge.svg)](https://coveralls.io/r/Richard-W/scalacrypt)

Scalacrypt provides advanced cryptographic functions for scala projects. It wraps the
javax.crypto API and provides a few things that are not implemented there in a way
usable for this project.

This project is under heavy development and not suited for production use!!!

To add scalacrypt to your sbt project just add the following line to your build.sbt:

```scala
libraryDependencies += "xyz.wiedenhoeft" %% "scalacrypt" % "0.4.0"
```

You can use the current snapshot by putting the following lines in your build.sbt:

```scala
resolvers += Resolver.sonatypeRepo("snapshots")

libraryDependencies += "xyz.wiedenhoeft" %% "scalacrypt" % "0.5-SNAPSHOT"
```

As the API is subject to heavy changes i recommend you use "sbt doc" to get definitive reference.
Im doing my best to keep the documentation and this README up-to-date but as long as i did not
stabilize the API it might sometimes be a little off.

Symmetric encryption
--------------------

Symmetric encryption in scalacrypt is achieved by combining a BlockCipher, a BlockPadding and a BlockCipherMode.
These objects can be combined inside a BlockCipherSuite object which drives the encryption and calls the appropriate
methods on the primitives. It provides the encrypt and the decrypt methods.

Example for constructing a BlockCipherSuite. You have to make sure yourself that the IV is valid.
```scala
import blockciphers.AES128
import modes.CBC
import paddings.PKCS7Padding

val params = Parameters(
	'symmetricKey128 -> Key.generate[SymmetricKey128],
	'iv -> Random.nextBytes(16)
)

// When you dynamically build the params object you might want to match the
// Try objects for error handling
val aes = BlockCipher[AES128](params).get
val cbc = BlockCipherMode[CBC](params).get
val pkcs7 = BlockPadding[PKCS7Padding](params).get

val suite = new BlockCipherSuite(aes, cbc, pkcs7)
```

There are certain helper functions in the 'suites' package. They automatically validate parameters and return a Try.

```scala
val suite = suites.AES128_CBC_PKCS7Padding(Key.generate[SymmetricKey128], None).get
val iv = suite.params('iv)
val key = suite.params('symmetricKey128)
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

Message authentication
----------------------

The KeyedHash trait provides an interface for various methods for authenticating message.

```scala
import khash.HmacSHA256

val message = "Hello world!".getBytes
val falseMessage = "Bye world!".getBytes

val hmacKey = "somepassword".getBytes.toSeq.toKey[SymmetricKeyArbitrary].get
val mac = HmacSHA256(hmacKey, message).get

println(HmacSHA256.verify(hmacKey, message, mac).get) //prints true
println(HmacSHA256.verify(hmacKey, falseMessage, mac).get) //prints false
```

Also an RSASSA-PSS signing algorithm is implemented using the KeyedHash trait:

```scala
import khash.RSASSA_PSS
import hash.SHA256

val privateKey = Key.generate[RSAKey]
val publicKey = privateKey.publicKey

val message = "Hello World".getBytes
val falseMessage = "Bye world!".getBytes

val signer = RSASSA_PSS(SHA256, 32)
val signature = signer(privateKey, message).get

println(signer.verify(publicKey, message, signature).get) // Prints true
println(signer.verify(publicKey, falseMessage, signature).get) // Prints false
```

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
