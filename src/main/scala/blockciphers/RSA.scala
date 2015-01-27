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
package xyz.wiedenhoeft.scalacrypt.blockciphers

import xyz.wiedenhoeft.scalacrypt._
import scala.util.{ Try, Success, Failure }

/** BlockCipher that encrypts a byte sequence using RSA.
  *
  * Because of the internal representation of the data
  * leading zeroes will be lost. You should use a padding
  * scheme that fixes this case.
  */
trait RSA extends BlockCipher[RSAKey] {

  lazy val blockSize = (key.n.bitLength.toFloat / 8.0).ceil.toInt

  def encryptBlock(block: Seq[Byte]): Try[Seq[Byte]] = {
    val m = block.toBigInt
    if(m > key.n) return Failure(new EncryptionException("Message is bigger than modulus."))

    val c = m modPow (key.e, key.n)
    Success(c.toBytes)
  }

  def decryptBlock(block: Seq[Byte]): Try[Seq[Byte]] = {
    val c = block.toBigInt
    if(c > key.n) return Failure(new DecryptionException("Invalid ciphertext"))

    key.d match {
      case Some(d) ⇒
      val m = c modPow (d, key.n)
      Success(m.toBytes)

      case _ ⇒
      Failure(new DecryptionException("No private key."))
    }
  }
}
