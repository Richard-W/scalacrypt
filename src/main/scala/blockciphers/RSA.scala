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
sealed trait RSA extends BlockCipher[RSAKey] {

  lazy val blockSize = (key.n.bitLength.toFloat / 8.0).ceil.toInt

  def encryptBlock(block: Seq[Byte]): Try[Seq[Byte]] = {
    val blocklen = block.length
    if(blocklen != blockSize)
      return Failure(new EncryptionException(s"Invalid block size. Expected length $blockSize, got $blocklen."))

    val m = block.os2ip
    if(m > key.n) return Failure(new EncryptionException("Message representation out of range."))

    val c = m modPow (key.e, key.n)
    c.i2osp(blockSize)
  }

  def decryptBlock(block: Seq[Byte]): Try[Seq[Byte]] = {
    if(block.length != blockSize) return Failure(new DecryptionException("Invalid block size"))

    val c = block.os2ip
    if(c > key.n) return Failure(new DecryptionException("Invalid ciphertext"))

    key.privateKey match {
      case Some(RSAPrivateCombinedKeyPart(_, p, q, dP, dQ, qInv)) ⇒
        val c1 = c modPow (dP, p)
        val c2 = c modPow (dQ, q)
        (((qInv * (c1 - c2)) mod p) * q + c2).i2osp(blockSize)

      case Some(RSAPrivatePrimeKeyPart(p, q, dP, dQ, qInv)) ⇒
        val c1 = c modPow (dP, p)
        val c2 = c modPow (dQ, q)
        (((qInv * (c1 - c2)) mod p) * q + c2).i2osp(blockSize)

      case Some(RSAPrivateExponentKeyPart(d)) ⇒
        val m = c modPow (d, key.n)
        m.i2osp(blockSize)

      case None ⇒
        Failure(new DecryptionException("No private key."))
    }
  }
}

object RSA {

  implicit val builder = new CanBuildBlockCipher[RSA] {
    def build(parameters: Parameters): Try[RSA] = {
      Parameters.checkParam[RSAKey](parameters, 'rsaKey) match {
        case Success(k) ⇒ Success(new RSA { val key = k; val params = parameters })
        case Failure(f) ⇒ Failure(f)
      }
    }
  }
}
