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
package xyz.wiedenhoeft.scalacrypt.suites

import xyz.wiedenhoeft.scalacrypt._
import scala.util.{ Try, Success, Failure }

object AES128_CBC_NoPadding {

  def apply(key: SymmetricKey128, iv: Option[Seq[Byte]] = None): Try[SymmetricBlockCipherSuite[SymmetricKey128] with blockciphers.AES128 with modes.CBC with paddings.NoPadding] = {
    val initVector = iv match {
      case Some(s) ⇒
      s

      case _ ⇒
      Random.nextBytes(16)
    }
    val k = key

    if(initVector.length != 16) {
      Failure(new IllegalArgumentException("IV must be 16 bytes long."))
    }

    Success(new SymmetricBlockCipherSuite[SymmetricKey128] with blockciphers.AES128 with modes.CBC with paddings.NoPadding {
      lazy val key = k
      lazy val iv = initVector
    })
  }
}

object AES192_CBC_NoPadding {

  def apply(key: SymmetricKey192, iv: Option[Seq[Byte]] = None): Try[SymmetricBlockCipherSuite[SymmetricKey192] with blockciphers.AES192 with modes.CBC with paddings.NoPadding] = {
    val initVector = iv match {
      case Some(s) ⇒
      s

      case _ ⇒
      Random.nextBytes(16)
    }
    val k = key

    if(initVector.length != 16) {
      Failure(new IllegalArgumentException("IV must be 16 bytes long."))
    }

    Success(new SymmetricBlockCipherSuite[SymmetricKey192] with blockciphers.AES192 with modes.CBC with paddings.NoPadding {
      lazy val key = k
      lazy val iv = initVector
    })
  }
}

object AES256_CBC_NoPadding {

  def apply(key: SymmetricKey256, iv: Option[Seq[Byte]] = None): Try[SymmetricBlockCipherSuite[SymmetricKey256] with blockciphers.AES256 with modes.CBC with paddings.NoPadding] = {
    val initVector = iv match {
      case Some(s) ⇒
      s

      case _ ⇒
      Random.nextBytes(16)
    }
    val k = key

    if(initVector.length != 16) {
      Failure(new IllegalArgumentException("IV must be 16 bytes long."))
    }

    Success(new SymmetricBlockCipherSuite[SymmetricKey256] with blockciphers.AES256 with modes.CBC with paddings.NoPadding {
      lazy val key = k
      lazy val iv = initVector
    })
  }
}

