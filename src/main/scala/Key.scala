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

/**
 * A wrapper for a sequence of bytes used
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
  def generate[KeyType <: Key: CanGenerateKey]: KeyType = implicitly[CanGenerateKey[KeyType]].generate
}

/** Adds the toKey method to Any. */
final class MightBuildKeyOp[FromType](value: FromType) {

  /** Tries to convert the object to a specific implementation of Key. */
  def toKey[KeyType <: Key]()(implicit builder: MightBuildKey[FromType, KeyType]) = {
    builder.tryBuild(value)
  }
}
