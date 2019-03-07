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
package xyz.wiedenhoeft.scalacrypt.suites

import xyz.wiedenhoeft.scalacrypt._
import scala.util.{ Try, Success, Failure }
import blockciphers._
import modes._
import paddings._

object Threefish256_CBC_PKCS7Padding {

  def apply(key: SymmetricKey256, iv: Option[Seq[Byte]] = None, tweak: Option[Seq[Byte]] = None): Try[BlockCipherSuite[SymmetricKey256]] = {
    val params = Parameters(
      'symmetricKey256 -> key,
      'iv -> (iv match {
        case Some(s) ⇒ s
        case _ ⇒ Random.nextBytes(32)
      }),
      'tweak -> (tweak match {
        case Some(s) ⇒ s
        case _ ⇒ Random.nextBytes(16)
      }))

    BlockCipher[Threefish256](params) flatMap { cipher ⇒
      BlockCipherMode[CBC](params) flatMap { mode ⇒
        BlockPadding[PKCS7Padding](params) map { padding ⇒
          new BlockCipherSuite(cipher, mode, padding)
        }
      }
    }
  }
}

object Threefish512_CBC_PKCS7Padding {

  def apply(key: SymmetricKey512, iv: Option[Seq[Byte]] = None, tweak: Option[Seq[Byte]] = None): Try[BlockCipherSuite[SymmetricKey512]] = {
    val params = Parameters(
      'symmetricKey512 -> key,
      'iv -> (iv match {
        case Some(s) ⇒ s
        case _ ⇒ Random.nextBytes(64)
      }),
      'tweak -> (tweak match {
        case Some(s) ⇒ s
        case _ ⇒ Random.nextBytes(16)
      }))

    BlockCipher[Threefish512](params) flatMap { cipher ⇒
      BlockCipherMode[CBC](params) flatMap { mode ⇒
        BlockPadding[PKCS7Padding](params) map { padding ⇒
          new BlockCipherSuite(cipher, mode, padding)
        }
      }
    }
  }
}

object Threefish1024_CBC_PKCS7Padding {

  def apply(key: SymmetricKey1024, iv: Option[Seq[Byte]] = None, tweak: Option[Seq[Byte]] = None): Try[BlockCipherSuite[SymmetricKey1024]] = {
    val params = Parameters(
      'symmetricKey1024 -> key,
      'iv -> (iv match {
        case Some(s) ⇒ s
        case _ ⇒ Random.nextBytes(128)
      }),
      'tweak -> (tweak match {
        case Some(s) ⇒ s
        case _ ⇒ Random.nextBytes(16)
      }))

    BlockCipher[Threefish1024](params) flatMap { cipher ⇒
      BlockCipherMode[CBC](params) flatMap { mode ⇒
        BlockPadding[PKCS7Padding](params) map { padding ⇒
          new BlockCipherSuite(cipher, mode, padding)
        }
      }
    }
  }
}
