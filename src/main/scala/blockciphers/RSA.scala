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
  private def byteToInt(byte: Byte): Int = {
    val result = byte.toInt
    if(result < 0) result + 256
    else result
  }

  private def bytesToInt(bytes: Seq[Byte]): BigInt = {
    var result = BigInt(0)

    for(i <- (0 until bytes.length)) {
      val exponent = bytes.length - 1 - i
      result += BigInt(byteToInt(bytes(i))) * (BigInt(256) pow exponent)
    }

    result
  }

  private def intToBytes(int: BigInt): Seq[Byte] = {
    var remaining = int
    var result = Seq[Byte]()

    var exponent = 0
    var biggestNumber = BigInt(1)
    while(int > biggestNumber) {
      exponent += 1
      biggestNumber = BigInt(256) pow exponent
    }

    while(exponent > 0) {
      exponent -= 1

      val factor = BigInt(256) pow exponent
      val mod = remaining mod factor
      val difference = remaining - mod
      result = result :+ (difference / factor).toByte
      remaining = mod
    }

    result
  }

  lazy val blockSize = (key.n.bitLength.toFloat / 8.0).ceil.toInt

  def encryptBlock(block: Seq[Byte]): Try[Seq[Byte]] = {
    val m = bytesToInt(block)
    if(m > key.n) return Failure(new EncryptionException("Message is bigger than modulus."))

    val c = m modPow (key.e, key.n)
    Success(c.toByteArray)
  }

  def decryptBlock(block: Seq[Byte]): Try[Seq[Byte]] = {
    val c = BigInt(block.toArray)
    if(c > key.n) return Failure(new DecryptionException("Invalid ciphertext"))

    key.d match {
      case Some(d) ⇒
      val m = c modPow (d, key.n)
      Success(intToBytes(m))

      case _ ⇒
      Failure(new DecryptionException("No private key."))
    }
  }
}
