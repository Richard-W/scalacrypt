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
trait CanBuildSymmetricKey[FromType, KeyType <: SymmetricKey] {

  /** Tries to build the key from the given object. */
  def tryBuild(from: FromType): Try[KeyType]
}

/** Base trait for type classes generating random keys. */
trait CanGenerateSymmetricKey[KeyType <: SymmetricKey] {

  /** Generate symmetric key. */
  def generate: KeyType
}

/** Singleton used to construct key objects of arbitrary length. */
object SymmetricKey {

  /** Wraps a key into a Key-object. */
  def apply[KeyType <: SymmetricKey](from: Seq[Byte])(implicit builder: CanBuildSymmetricKey[Seq[Byte], KeyType]) = builder.tryBuild(from)

  /** Randomly generate a symmetric key. */
  def generate[KeyType <: SymmetricKey : CanGenerateSymmetricKey]: KeyType = implicitly[CanGenerateSymmetricKey[KeyType]].generate
}

/** A 128 bit symmetric key. */
sealed abstract class SymmetricKey128 extends SymmetricKey

/** A 192 bit symmetric key. */
sealed abstract class SymmetricKey192 extends SymmetricKey

/** A 256 bit symmetric key. */
sealed abstract class SymmetricKey256 extends SymmetricKey

/** A symmetric key of arbitrary length. */
sealed abstract class SymmetricKeyArbitrary extends SymmetricKey

object CanBuildSymmetricKey {

  /** Builder for 128 bit symmetric keys. */
  implicit val symmetricKey128 = new CanBuildSymmetricKey[Seq[Byte], SymmetricKey128] {

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
  implicit val symmetricKey192 = new CanBuildSymmetricKey[Seq[Byte], SymmetricKey192] {

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
  implicit val symmetricKey256 = new CanBuildSymmetricKey[Seq[Byte], SymmetricKey256] {

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
  implicit val symmetricKeyArbitrary = new CanBuildSymmetricKey[Seq[Byte], SymmetricKeyArbitrary] {

    def tryBuild(keyBytes: Seq[Byte]): Try[SymmetricKeyArbitrary] = {
      Success(new SymmetricKeyArbitraryImpl(keyBytes))
    }

    private class SymmetricKeyArbitraryImpl(keyBytes: Seq[Byte]) extends SymmetricKeyArbitrary {

      def length: Int = keyBytes.length

      def bytes: Seq[Byte] = keyBytes
    }
  }
}

object CanGenerateSymmetricKey {

  implicit val symmetricKey128 = new CanGenerateSymmetricKey[SymmetricKey128] {
    def generate = SymmetricKey[SymmetricKey128](Random.nextBytes(16)).get
  }

  implicit val symmetricKey192 = new CanGenerateSymmetricKey[SymmetricKey192] {
    def generate = SymmetricKey[SymmetricKey192](Random.nextBytes(24)).get
  }

  implicit val symmetricKey256 = new CanGenerateSymmetricKey[SymmetricKey256] {
    def generate = SymmetricKey[SymmetricKey256](Random.nextBytes(32)).get
  }

  implicit val symmetricKeyArbitrary = new CanGenerateSymmetricKey[SymmetricKeyArbitrary] {
    def generate = SymmetricKey[SymmetricKeyArbitrary](Random.nextBytes(32)).get
  }
}
