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

object AES128_CBC_PKCS7Padding {

  def apply(key: SymmetricKey128, iv: Option[Seq[Byte]] = None): Try[BlockCipherSuite[SymmetricKey128]] = {
    val params = Parameters(
      'symmetricKey128 -> key,
      'iv -> (iv match {
        case Some(s) ⇒ s
        case _ ⇒ Random.nextBytes(16)
      })
    )
    
    BlockCipher[AES128](params) flatMap { cipher ⇒
      BlockCipherMode[CBC](params) flatMap { mode ⇒
        BlockPadding[PKCS7Padding](params) map { padding ⇒
          new BlockCipherSuite(cipher, padding, mode)
        }
      }
    }
  }
}

object AES192_CBC_PKCS7Padding {

  def apply(key: SymmetricKey192, iv: Option[Seq[Byte]] = None): Try[BlockCipherSuite[SymmetricKey192]] = {
    val params = Parameters(
      'symmetricKey192 -> key,
      'iv -> (iv match {
        case Some(s) ⇒ s
        case _ ⇒ Random.nextBytes(16)
      })
    )
    
    BlockCipher[AES192](params) flatMap { cipher ⇒
      BlockCipherMode[CBC](params) flatMap { mode ⇒
        BlockPadding[PKCS7Padding](params) map { padding ⇒
          new BlockCipherSuite(cipher, padding, mode)
        }
      }
    }
  }
}

object AES256_CBC_PKCS7Padding {

  def apply(key: SymmetricKey256, iv: Option[Seq[Byte]] = None): Try[BlockCipherSuite[SymmetricKey256]] = {
    val params = Parameters(
      'symmetricKey256 -> key,
      'iv -> (iv match {
        case Some(s) ⇒ s
        case _ ⇒ Random.nextBytes(16)
      })
    )
    
    BlockCipher[AES256](params) flatMap { cipher ⇒
      BlockCipherMode[CBC](params) flatMap { mode ⇒
        BlockPadding[PKCS7Padding](params) map { padding ⇒
          new BlockCipherSuite(cipher, padding, mode)
        }
      }
    }
  }
}
