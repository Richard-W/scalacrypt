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
package xyz.wiedenhoeft.scalacrypt.util

import xyz.wiedenhoeft.scalacrypt._
import scala.util.{ Try, Success, Failure }

/**
 * Implements an easy way to hash passwords using PBKDF2.
 *
 * The verification process is backwards compatible.
 */
object PBKDF2Easy {
  lazy val algoMap = Map[Byte, KeyedHash[Key]](
    1.toByte -> khash.HmacSHA256
  )

  lazy val defaultAlgorithm = 1.toByte
  val defaultSaltLength = 32
  val defaultHashLength = 32

  lazy val defaultSaltLengthBytes = java.nio.ByteBuffer.allocate(4).putInt(defaultSaltLength).array.toList
  lazy val defaultHashLengthBytes = java.nio.ByteBuffer.allocate(4).putInt(defaultHashLength).array.toList

  def apply(password: Seq[Byte], iterations: Int = 20000): Try[Seq[Byte]] = {
    val key = password.toKey[SymmetricKeyArbitrary].get
    val iterationsBytes = java.nio.ByteBuffer.allocate(4).putInt(iterations).array.toList
    val pbkdf2 = khash.PBKDF2(algoMap(defaultAlgorithm), iterations, defaultHashLength)

    val salt = Random.nextBytes(32).toList
    pbkdf2(key, salt) map { _.toList } match {
      case Success(hash) ⇒
        Success(defaultAlgorithm :: iterationsBytes ::: defaultSaltLengthBytes ::: salt ::: defaultHashLengthBytes ::: hash)

      case Failure(f) ⇒
        Failure(f)
    }
  }

  def verify(password: Seq[Byte], hash: Seq[Byte]): Try[Boolean] = {
    if (hash.length < 9 || !algoMap.contains(hash(0))) return Success(false)

    val key = password.toKey[SymmetricKeyArbitrary].get
    val algorithm = algoMap(hash(0))
    val iterations = java.nio.ByteBuffer.allocate(4).put(hash.slice(1, 5).toArray).getInt(0)
    val saltLength = java.nio.ByteBuffer.allocate(4).put(hash.slice(5, 9).toArray).getInt(0)

    val slice1 = hash.slice(9, hash.length)
    if (slice1.length < saltLength) return Success(false)

    val salt = slice1.slice(0, saltLength)

    val slice2 = slice1.slice(saltLength, slice1.length)
    if (slice2.length < 4) return Success(false)

    val hashLength = java.nio.ByteBuffer.allocate(4).put(slice2.slice(0, 4).toArray).getInt(0)

    val realHash = slice2.slice(4, slice2.length)
    if (realHash.length != hashLength) return Success(false)

    val pbkdf2 = khash.PBKDF2(algorithm, iterations, hashLength)
    pbkdf2(key, salt) map { _ == realHash }
  }
}
