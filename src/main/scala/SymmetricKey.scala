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

/** Singleton used to construct key objects of arbitrary length. */
object SymmetricKey {

  /** Wraps a key into a Key-object. */
  def apply(keyBytes: Seq[Byte]): SymmetricKey = {
    new SymmetricKeyImpl(keyBytes)
  }

  /** Implementation of the Key trait. */
  private class SymmetricKeyImpl(key: Seq[Byte]) extends SymmetricKey {
    
    def length: Int = {
      key.length
    }

    def bytes: Seq[Byte] = {
      key
    }
  }
}

sealed abstract class SymmetricKey128 extends SymmetricKey
sealed abstract class SymmetricKey192 extends SymmetricKey
sealed abstract class SymmetricKey256 extends SymmetricKey

object SymmetricKey128 {

  def apply(keyBytes: Seq[Byte]): Try[SymmetricKey128] = {
    if(keyBytes.length == 128 / 8) {
      Success(new SymmetricKey128Impl(keyBytes))
    } else {
      Failure(new KeyException("Illegal key size. Key should be exactly 128 bit/16 byte long."))
    }
  }

  def generate: SymmetricKey128 = {
    new SymmetricKey128Impl(Random.nextBytes(128 / 8))
  }

  private class SymmetricKey128Impl(keyBytes: Seq[Byte]) extends SymmetricKey128 {

    def length: Int = 128 / 8

    def bytes: Seq[Byte] = keyBytes
  }
}

object SymmetricKey192 {

  def apply(keyBytes: Seq[Byte]): Try[SymmetricKey192] = {
    if(keyBytes.length == 192 / 8) {
      Success(new SymmetricKey192Impl(keyBytes))
    } else {
      Failure(new KeyException("Illegal key size. Key should be exactly 192 bit/24 byte long."))
    }
  }

  def generate: SymmetricKey192 = {
    new SymmetricKey192Impl(Random.nextBytes(192 / 8))
  }

  private class SymmetricKey192Impl(keyBytes: Seq[Byte]) extends SymmetricKey192 {

    def length: Int = 192 / 8

    def bytes: Seq[Byte] = keyBytes
  }
}

object SymmetricKey256 {

  def apply(keyBytes: Seq[Byte]): Try[SymmetricKey256] = {
    if(keyBytes.length == 256 / 8) {
      Success(new SymmetricKey256Impl(keyBytes))
    } else {
      Failure(new KeyException("Illegal key size. Key should be exactly 256 bit/32 byte long."))
    }
  }

  def generate: SymmetricKey256 = {
    new SymmetricKey256Impl(Random.nextBytes(256 / 8))
  }

  private class SymmetricKey256Impl(keyBytes: Seq[Byte]) extends SymmetricKey256 {

    def length: Int = 256 / 8

    def bytes: Seq[Byte] = keyBytes
  }
}
