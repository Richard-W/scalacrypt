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
package xyz.wiedenhoeft.scalacrypt.khash

import xyz.wiedenhoeft.scalacrypt._
import iteratees._
import scala.util.{ Try, Success, Failure }

class Hmac(hash: Hash) extends KeyedHash[Key] {

  def apply(key: Key): Try[Iteratee[Seq[Byte], Seq[Byte]]] = {
    val key1 = if (key.length > hash.blockSize) {
      hash(key.bytes)
    } else {
      key.bytes
    }

    val key2 = key1 ++ Seq.fill[Byte](hash.blockSize - key1.length) { 0.toByte }

    val oKeyPad = Seq.fill[Byte](hash.blockSize)(0x5c.toByte) xor key2
    val iKeyPad = Seq.fill[Byte](hash.blockSize)(0x36.toByte) xor key2

    Success(
      hash.apply.fold(Element(iKeyPad)) map { innerHash ⇒
        hash(oKeyPad ++ innerHash)
      }
    )
  }

  def verify(key: Key, hash: Seq[Byte]): Try[Iteratee[Seq[Byte], Boolean]] = apply(key) map { _ map { _ == hash } }

  val length = hash.length
}

import hash._

/** HMAC-SHA1 implementation of Mac. */
object HmacSHA1 extends Hmac(SHA1)

/** HMAC-SHA256 implementation of Mac. */
object HmacSHA256 extends Hmac(SHA256)
