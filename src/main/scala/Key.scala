/* Copyright 2014, 2015 Richard Wiedenhöft <richard@wiedenhoeft.xyz>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package xyz.wiedenhoeft.scalacrypt

import scala.util.{ Try, Success, Failure }

/** A wrapper for a sequence of bytes used
  * as a key for encryption.
  */
trait Key extends Equals {

  /** Length of the key in bytes. */
  def length: Int

  /** The actual key. */
  def bytes: Seq[Byte]

  /** Inherited from Equals trait. */
  def canEqual(other: Any): Boolean = other match {
    case _: Key ⇒
    true

    case _ ⇒
    false
  }

  /** Equality test */
  override def equals(other: Any): Boolean = other match {
    case k: Key ⇒
    this.bytes == k.bytes

    case _ ⇒
    false
  }
}

/** Base trait for symmetric key builders. */
trait MightBuildKey[-FromType, KeyType <: Key] {

  /** Tries to build the key from the given object. */
  def tryBuild(from: FromType): Try[KeyType]
}

/** Base trait for type classes generating random keys. */
trait CanGenerateKey[KeyType <: Key] {

  /** Generate symmetric key. */
  def generate: KeyType
}

/** Singleton used to construct key objects of arbitrary length. */
object Key {

  /** Randomly generate a symmetric key. */
  def generate[KeyType <: Key : CanGenerateKey]: KeyType = implicitly[CanGenerateKey[KeyType]].generate
}

/** A 128 bit symmetric key. */
sealed abstract class SymmetricKey128 extends Key

/** A 192 bit symmetric key. */
sealed abstract class SymmetricKey192 extends Key

/** A 256 bit symmetric key. */
sealed abstract class SymmetricKey256 extends Key

/** A symmetric key of arbitrary length. */
sealed abstract class SymmetricKeyArbitrary extends Key

/** A private key that only holds the private exponent. */
final class RSAPrivateKeyV1(val d: BigInt) { }

/** A private key part that holds parameters for faster application of the private key. */
final class RSAPrivateKeyV2(val p: BigInt, val q: BigInt, val dP: BigInt, val dQ: BigInt, val qInv: BigInt) { }

/** Asymmetric RSA key. */
sealed abstract class RSAKey extends Key {

  /** RSA modulus. */
  val n: BigInt

  /** Public exponent. */
  val e: BigInt

  val privateKey1: Option[RSAPrivateKeyV1]

  val privateKey2: Option[RSAPrivateKeyV2]

  /** Whether this key should be kept secret. */
  def isPrivateKey: Boolean = if(privateKey1.isDefined || privateKey2.isDefined) true else false

  /** Whether it is safe to publish this key. */
  def isPublicKey: Boolean = !isPrivateKey

  /** Returns a RSA key that contains only the public parts. */
  def publicKey: RSAKey = {
    val base = this
    new RSAKey {
      val n = base.n
      val e = base.e
      val privateKey1 = None
      val privateKey2 = None
    }
  }

  def length = (n.bitLength.toFloat / 8.0).ceil.toInt

  def bytes: Seq[Byte] = {
    def f(identifier: Int, value: BigInt): List[Byte] = {
      val byteArray: List[Byte] = value.toByteArray.toList
      val lengthBytes: List[Byte] = java.nio.ByteBuffer.allocate(4).putInt(byteArray.length).array.toList
      identifier.toByte :: lengthBytes ::: byteArray ::: Nil
    }

    f(0, n) ::: f(1, e) :::
      (if(privateKey1.isDefined) f(2, privateKey1.get.d) else Nil) :::
      (if(privateKey2.isDefined) {
        val k2 = privateKey2.get
        f(3, k2.p) :::
          f(4, k2.q) :::
          f(5, k2.dP) :::
          f(6, k2.dQ) :::
          f(7, k2.qInv) :::
          Nil
      } else Nil)
  }
}

/** Adds the toKey method to Any. */
final class MightBuildKeyOp[FromType](value: FromType) {

  /** Tries to convert the object to a specific implementation of Key. */
  def toKey[KeyType <: Key]()(implicit builder: MightBuildKey[FromType, KeyType]) = {
    builder.tryBuild(value)
  }
}

object MightBuildKey {

  /** Builder for 128 bit symmetric keys. */
  implicit val symmetricKey128 = new MightBuildKey[Seq[Byte], SymmetricKey128] {

    def tryBuild(keyBytes: Seq[Byte]): Try[SymmetricKey128] = {
      if(keyBytes.length == 128 / 8) {
        Success(new SymmetricKey128Impl(keyBytes))
      } else {
        Failure(new KeyException("Illegal key size. Key should be exactly 128 bit/16 byte long."))
      }
    }

    private class SymmetricKey128Impl(keyBytes: Seq[Byte]) extends SymmetricKey128 {

      def length: Int = 16

      def bytes: Seq[Byte] = keyBytes
    }
  }

  /** Builder for 192 bit symmetric keys. */
  implicit val symmetricKey192 = new MightBuildKey[Seq[Byte], SymmetricKey192] {

    def tryBuild(keyBytes: Seq[Byte]): Try[SymmetricKey192] = {
      if(keyBytes.length == 192 / 8) {
        Success(new SymmetricKey192Impl(keyBytes))
      } else {
        Failure(new KeyException("Illegal key size. Key should be exactly 192 bit/24 byte long."))
      }
    }

    private class SymmetricKey192Impl(keyBytes: Seq[Byte]) extends SymmetricKey192 {

      def length: Int = 24

      def bytes: Seq[Byte] = keyBytes
    }
  }

  /** Builder for 256 bit symmetric keys. */
  implicit val symmetricKey256 = new MightBuildKey[Seq[Byte], SymmetricKey256] {

    def tryBuild(keyBytes: Seq[Byte]): Try[SymmetricKey256] = {
      if(keyBytes.length == 256 / 8) {
        Success(new SymmetricKey256Impl(keyBytes))
      } else {
        Failure(new KeyException("Illegal key size. Key should be exactly 256 bit/32 byte long."))
      }
    }

    private class SymmetricKey256Impl(keyBytes: Seq[Byte]) extends SymmetricKey256 {

      def length: Int = 32

      def bytes: Seq[Byte] = keyBytes
    }
  }

  /** Builder for symmetric keys of arbitrary length. */
  implicit val symmetricKeyArbitrary = new MightBuildKey[Seq[Byte], SymmetricKeyArbitrary] {

    def tryBuild(keyBytes: Seq[Byte]): Try[SymmetricKeyArbitrary] = {
      Success(new SymmetricKeyArbitraryImpl(keyBytes))
    }

    private class SymmetricKeyArbitraryImpl(keyBytes: Seq[Byte]) extends SymmetricKeyArbitrary {

      def length: Int = keyBytes.length

      def bytes: Seq[Byte] = keyBytes
    }
  }

  implicit val publicRsaKeyFromTuple = new MightBuildKey[(Seq[Byte], Seq[Byte]), RSAKey] {
    def tryBuild(keyTuple: (Seq[Byte], Seq[Byte])): Try[RSAKey] = Success(new RSAKey {
      val n = keyTuple._2.os2ip
      val e = keyTuple._1.os2ip
      val privateKey1 = None
      val privateKey2 = None
    })
  }

  implicit val privateRsaKeyFromTuple = new MightBuildKey[(Seq[Byte], Seq[Byte], Seq[Byte]), RSAKey] {
    def tryBuild(keyTuple: (Seq[Byte], Seq[Byte], Seq[Byte])): Try[RSAKey] = Success(new RSAKey {
      val n = keyTuple._3.os2ip
      val e = keyTuple._1.os2ip
      val privateKey1 = Some(new RSAPrivateKeyV1(keyTuple._2.os2ip))
      val privateKey2 = None
    })
  }

  implicit val rsaKeyFromBytes = new MightBuildKey[Seq[Byte], RSAKey] {

    def tryBuild(keyBytes: Seq[Byte]): Try[RSAKey] = {
      def createMap(map: Map[Int, BigInt], bytes: Seq[Byte]): Try[Map[Int, BigInt]] = {
        if(bytes.length == 0) {
          Success(Map[Int, BigInt]())
        } else if(bytes.length < 5) {
          Failure(new KeyException("Invalid length of RSA key."))
        } else {
          val identifier = bytes(0)
          val length = java.nio.ByteBuffer.allocate(4).put(bytes.slice(1, 5).toArray).getInt(0)
          val withoutHeader = bytes.slice(5, bytes.length)
          if(withoutHeader.length < length) {
            Failure(new KeyException("Invalid length of RSA key."))
          } else {
            val data = withoutHeader.slice(0, length)
            val newMap = map + ((identifier.toInt, BigInt(data.toArray)))
            createMap(newMap, withoutHeader.slice(length, withoutHeader.length)) match {
              case Success(rMap) ⇒
              Success(newMap ++ rMap)

              case f: Failure[_] ⇒
              f
            }
          }
        }
      }

      val map: Map[Int, BigInt] = createMap(Map[Int, BigInt](), keyBytes) match {
        case Success(m) ⇒
        m

        case f: Failure[_] ⇒
        return f.asInstanceOf[Try[RSAKey]]
      }

      val key1: Option[RSAPrivateKeyV1] = if(map.contains(2))
        Some(new RSAPrivateKeyV1(map(2)))
      else
        None

      val key2: Option[RSAPrivateKeyV2] = if((3 to 7).map({ map.contains(_) }).filter({ !_ }).length == 0)
        Some(new RSAPrivateKeyV2(map(3), map(4), map(5), map(6), map(7)))
      else
        None

      if(! map.contains(0) || !map.contains(1)) {
        Failure(new KeyException("Important parameters missing in RSAKey."))
      } else Success(new RSAKey {
        val n = map.get(0).get
        val e = map.get(1).get
        val privateKey1 = key1
        val privateKey2 = key2
      })
    }
  }
}

object CanGenerateKey {

  implicit val symmetricKey128 = new CanGenerateKey[SymmetricKey128] {
    def generate = Random.nextBytes(16).toKey[SymmetricKey128].get
  }

  implicit val symmetricKey192 = new CanGenerateKey[SymmetricKey192] {
    def generate = Random.nextBytes(24).toKey[SymmetricKey192].get
  }

  implicit val symmetricKey256 = new CanGenerateKey[SymmetricKey256] {
    def generate = Random.nextBytes(32).toKey[SymmetricKey256].get
  }

  implicit val symmetricKeyArbitrary = new CanGenerateKey[SymmetricKeyArbitrary] {
    def generate = Random.nextBytes(32).toKey[SymmetricKeyArbitrary].get
  }

  implicit val rsaKey = new CanGenerateKey[RSAKey] {
    def generate = new RSAKey {
      // FIXME: Use secure PRNG.
      val p = BigInt.probablePrime(2048, scala.util.Random)
      val q = BigInt.probablePrime(2048, scala.util.Random)

      // Public Key
      val n = p * q
      val e = BigInt(65537)

      // Private key variant 1
      val ϕ = (p - 1) * (q - 1)
      val d = e modInverse ϕ
      val privateKey1 = Some(new RSAPrivateKeyV1(d))

      // Private key variant 2
      val dP = d mod (p - 1)
      val dQ = d mod (q - 1)
      val qInv = q modInverse p
      val privateKey2 = Some(new RSAPrivateKeyV2(p, q, dP, dQ, qInv))
    }
  }
}
