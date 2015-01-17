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
package xyz.wiedenhoeft.scalacrypt.misc

import scala.util.{ Try, Success, Failure }
import xyz.wiedenhoeft.scalacrypt._
import khash._

/** Implementation of the password based key derivation function 2. */
class PBKDF2(algorithm: KeyedHash) {
  def apply(password: SymmetricKey, salt: Seq[Byte], iterations: Int, length: Int): Seq[Byte] = {
    val numBlocks = (length.toFloat / algorithm.length).ceil.toInt
    var output = Seq[Byte]()

    for(block <- 1 until numBlocks + 1) {
      var buffer: Seq[Byte] = algorithm(salt ++ java.nio.ByteBuffer.allocate(4).putInt(block).array, password)
      var u: Seq[Byte] = buffer

      for(i <- 2 until (iterations + 1)) {
        u = algorithm(u, password)
        buffer = for(j <- 0 until u.length) yield (buffer(j) ^ u(j)).toByte
      }

      output = output ++ buffer
    }

    output.slice(0, length)
  }
}

object PBKDF2HmacSHA1 extends PBKDF2(HmacSHA1)

object PBKDF2HmacSHA256 extends PBKDF2(HmacSHA256)
