/* Copyright 2014 Richard Wiedenhoeft <richard@wiedenhoeft.xyz>
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

/** Adds the toKey method to Any. */
final class MightBuildKeyOp[FromType](val value: FromType) {

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
}
