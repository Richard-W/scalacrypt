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
import hash._
import blockciphers._
import modes._
import paddings._

object RSAES_OAEP {

  def apply(k: RSAKey, label: Seq[Byte] = Seq[Byte](), hash: Hash = SHA256, genSeed: (Int) ⇒ Seq[Byte] = { length ⇒ Random.nextBytes(length) }): Try[BlockCipherSuite[RSAKey]] = {
    val params = Parameters(
      'rsaKey -> k,
      'label -> label,
      'hash -> hash,
      'generator -> genSeed
    )

    BlockCipher[RSA](params) flatMap { cipher ⇒
      BlockCipherMode[ECB](params) flatMap { mode ⇒
        BlockPadding[OAEP](params) map { padding ⇒
          new BlockCipherSuite(cipher, padding, mode)
        }
      }
    }
  }
}
