Scalacrypt
==========

Scalacrypt provides advanced cryptographic functions for scala projects. It wraps the
javax.crypto API and provides a few things that are not implemented there. So far
this project only provides symmetric encryption. This may change in the future.

This project is under heavy development and not suited for production!!!

To add this scalacrypt to your sbt project just add the following line to your build.sbt:

```scala
libraryDependencies += "xyz.wiedenhoeft" %% "scalacrypt" % "0.2.0"
```

You can use the current snapshot by putting the following lines in your build.sbt:

```scala
resolvers += Resolver.sonatypeRepo("snapshots")

libraryDependencies += "xyz.wiedenhoeft" %% "scalacrypt" % "0.3-SNAPSHOT"
```

Symmetric encryption
--------------------

This library contains the trait SymmetricBlockCipher:

```scala
/** Base trait for symmetric block ciphers such as AES. */
trait SymmetricBlockCipher[KeyType <: SymmetricKey] {

  /** Block size in bytes. */
  val blockSize: Int

  /** Returns a function that encrypts single blocks using the key. */
  def encrypt(key: KeyType): Seq[Byte] ⇒ Try[Seq[Byte]]

  /** Returns a function that decrypts single blocks using the key. */
  def decrypt(key: KeyType): Seq[Byte] ⇒ Try[Seq[Byte]]
}
```

KeyType is a specific child of SymmetricKey. For AES256 it is SymmetricKey256 for example.
You get the idea. The predefined key classes can be instantiated using the following
methods:

```scala
// SymmetricKey.apply[KeyType <: SymmetricKey](keyBytes: Seq[Byte])(implicit CanBuildSymmetricKeyFromByteSequence[KeyType]): Try[KeyType]
val specificKey = SymmetricKey[SymmetricKey128](0 until 16 map { _.toByte }) match { case Success(s) ⇒ s case Failure(f) ⇒ throw f }

// SymmetricKey.generate[KeyType <: SymmetricKey]()(implicit CanBuildSymmetricKeyFromByteSequence[KeyType]): KeyType
val randomKey = SymmetricKey.generate[SymmetricKey128]
```

The function returned by encrypt and decrypt is able to encrypt a single block so in the case of AES exactly 16 bytes. If your input is not
exactly divisible by the block size you need padding. The BlockPadding trait transforms an Iterator of byte sequences to an Iterator of
properly padded blocks.

Contributing
------------

* Bug reports are appreciated as much as actual code contributions. Do not hesitate to report if you encounter a problem.
* All parts of this library MUST never throw exceptions. Functions should return a Try if they might fail. Also if you encounter an exception i consider it a bug and would appreciate if you reported it here.
* The library should be kept extensible. It MUST not be necessary to contribute to this library to implement new algorithms. However if you think an algorithm might be of use for others do not hesitate to merge it.
* This project was born out of necessity. There seems to be no other project in scala providing this functionality and i needed it. I am no cryptography expert but i read a few articles about best practices for encryption. You are welcome to tell me where i am wrong. In fact i will not consider this project stable until a few people who **really** know what they are doing reviewed it.
