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
trait SymmetricKey {

  /** Length of the key in bytes. */
  def length: Int

  /** The actual key. */
  def bytes: Seq[Byte]
}

/** Base trait for symmetric key builders. */
trait CanBuildSymmetricKeyFrom[FromType,KeyType <: SymmetricKey] {

  /** Tries to build the key from the given object. */
  def tryBuild(from: FromType): Try[KeyType]
}

/** Specialized trait for building symmetric keys from byte sequences. */
trait CanBuildSymmetricKeyFromBytes[KeyType <: SymmetricKey] extends CanBuildSymmetricKeyFrom[Seq[Byte],KeyType]{

  /** A sequence length that guarantees that tryBuild succeeds. */
  def defaultLength: Int
}

/** Singleton used to construct key objects of arbitrary length. */
object SymmetricKey {

  /** Wraps a key into a Key-object. */
  def apply[KeyType <: SymmetricKey](keyBytes: Seq[Byte])(implicit builder: CanBuildSymmetricKeyFromBytes[KeyType]): Try[KeyType] = {
    builder.tryBuild(keyBytes)
  }

  /** Randomly generate a symmetric key. */
  def generate[KeyType <: SymmetricKey]()(implicit builder: CanBuildSymmetricKeyFromBytes[KeyType]): KeyType = {
    builder.tryBuild(Random.nextBytes(builder.defaultLength)).get
  }
}
/** A 128 bit symmetric key. */
sealed abstract class SymmetricKey128 extends SymmetricKey

/** A 192 bit symmetric key. */
sealed abstract class SymmetricKey192 extends SymmetricKey

/** A 256 bit symmetric key. */
sealed abstract class SymmetricKey256 extends SymmetricKey

/** A symmetric key of arbitrary length. */
sealed abstract class SymmetricKeyArbitrary extends SymmetricKey

object CanBuildSymmetricKeyFromBytes {

  /** Builder for 128 bit symmetric keys. */
  implicit val symmetricKey128 = new CanBuildSymmetricKeyFromBytes[SymmetricKey128] {

    def tryBuild(keyBytes: Seq[Byte]): Try[SymmetricKey128] = {
      if(keyBytes.length == 128 / 8) {
        Success(new SymmetricKey128Impl(keyBytes))
      } else {
        Failure(new KeyException("Illegal key size. Key should be exactly 128 bit/16 byte long."))
      }
    }

    def defaultLength: Int = 16

    private class SymmetricKey128Impl(keyBytes: Seq[Byte]) extends SymmetricKey128 {

      def length: Int = 16

      def bytes: Seq[Byte] = keyBytes
    }
  }

  /** Builder for 192 bit symmetric keys. */
  implicit val symmetricKey192 = new CanBuildSymmetricKeyFromBytes[SymmetricKey192] {

    def tryBuild(keyBytes: Seq[Byte]): Try[SymmetricKey192] = {
      if(keyBytes.length == 192 / 8) {
        Success(new SymmetricKey192Impl(keyBytes))
      } else {
        Failure(new KeyException("Illegal key size. Key should be exactly 192 bit/24 byte long."))
      }
    }

    def defaultLength: Int = 24

    private class SymmetricKey192Impl(keyBytes: Seq[Byte]) extends SymmetricKey192 {

      def length: Int = 24

      def bytes: Seq[Byte] = keyBytes
    }
  }

  /** Builder for 256 bit symmetric keys. */
  implicit val symmetricKey256 = new CanBuildSymmetricKeyFromBytes[SymmetricKey256] {

    def tryBuild(keyBytes: Seq[Byte]): Try[SymmetricKey256] = {
      if(keyBytes.length == 256 / 8) {
        Success(new SymmetricKey256Impl(keyBytes))
      } else {
        Failure(new KeyException("Illegal key size. Key should be exactly 256 bit/32 byte long."))
      }
    }

    def defaultLength: Int = 32

    private class SymmetricKey256Impl(keyBytes: Seq[Byte]) extends SymmetricKey256 {

      def length: Int = 32

      def bytes: Seq[Byte] = keyBytes
    }
  }

  /** Builder for symmetric keys of arbitrary length. */
  implicit val symmetricKeyArbitrary = new CanBuildSymmetricKeyFromBytes[SymmetricKeyArbitrary] {

    def tryBuild(keyBytes: Seq[Byte]): Try[SymmetricKeyArbitrary] = {
      Success(new SymmetricKeyArbitraryImpl(keyBytes))
    }

    def defaultLength: Int = 32

    private class SymmetricKeyArbitraryImpl(keyBytes: Seq[Byte]) extends SymmetricKeyArbitrary {

      def length: Int = keyBytes.length

      def bytes: Seq[Byte] = keyBytes
    }
  }
}
