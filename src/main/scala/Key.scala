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

/** A wrapper for a sequence of bytes used
  * as a key for encryption.
  */
sealed trait Key {

  /** Length of the key in bytes. */
  def length: Int

  /** The actual key. */
  def bytes: Seq[Byte]
}

/** Singleton used to construct Key-objects. */
object Key {

  /** Wraps a key into a Key-object. */
  def apply(key: Seq[Byte]): Key = {
    new KeyImpl(key)
  }

  /** Implementation of the Key trait. */
  private class KeyImpl(key: Seq[Byte]) extends Key {
    
    def length: Int = {
      key.length
    }

    def bytes: Seq[Byte] = {
      key
    }
  }
}
