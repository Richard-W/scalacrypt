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

trait CanBuildSymmetricKeyFrom[FromType,KeyType <: SymmetricKey] {
  def tryBuild(from: FromType): Try[KeyType]
}

trait CanBuildSymmetricKeyFromByteSequence[KeyType <: SymmetricKey] extends CanBuildSymmetricKeyFrom[Seq[Byte],KeyType]{
  def defaultLength: Int
}

/** Singleton used to construct key objects of arbitrary length. */
object SymmetricKey {

  /** Wraps a key into a Key-object. */
  def apply[KeyType <: SymmetricKey](keyBytes: Seq[Byte])(implicit builder: CanBuildSymmetricKeyFromByteSequence[KeyType]): Try[KeyType] = {
    builder.tryBuild(keyBytes)
  }

  def generate[KeyType <: SymmetricKey]()(implicit builder: CanBuildSymmetricKeyFromByteSequence[KeyType]): KeyType = {
    builder.tryBuild(Random.nextBytes(builder.defaultLength)).get
  }
}
