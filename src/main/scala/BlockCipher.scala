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

/** Base trait for symmetric block ciphers such as AES. */
trait BlockCipher[KeyType <: Key] {

  /** Block size in bytes. */
  def blockSize: Int

  /** The key used for en- and decryption. */
  def key: KeyType

  /** Returns a function that encrypts single blocks using the key. */
  def encryptBlock(block: Seq[Byte]): Try[Seq[Byte]]

  /** Returns a function that decrypts single blocks using the key. */
  def decryptBlock(block: Seq[Byte]): Try[Seq[Byte]]
}
