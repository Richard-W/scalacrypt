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
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/** Base class for symmetric block ciphers that are implemented in the java crypto API. */
sealed trait SymmetricJavaBlockCipher[KeyType <: Key] extends BlockCipher[KeyType] {

  protected def algo: String

  lazy val blockSize: Int = Cipher.getInstance(algo + "/ECB/NoPadding").getBlockSize

  private val secretKey: java.security.Key = new SecretKeySpec(key.bytes.toArray, "AES")
  private val encryptor: Cipher = Cipher.getInstance(algo + "/ECB/NoPadding")
  encryptor.init(Cipher.ENCRYPT_MODE, secretKey)
  private val decryptor: Cipher = Cipher.getInstance(algo + "/ECB/NoPadding")
  decryptor.init(Cipher.DECRYPT_MODE, secretKey)

  private def crypt(block: Seq[Byte], encrypt: Boolean): Try[Seq[Byte]] = {
    if(block.length == blockSize) {
      if(encrypt) {
        Success(encryptor.doFinal(block.toArray))
      } else {
        Success(decryptor.doFinal(block.toArray))
      }
    } else {
      Failure(
        new IllegalBlockSizeException("Expected block of length " + blockSize + ", got " + block.length + " bytes.")
      )
    }
  }

  def encryptBlock(block: Seq[Byte]): Try[Seq[Byte]] = crypt(block, true)

  def decryptBlock(block: Seq[Byte]): Try[Seq[Byte]] = crypt(block, false)
}

sealed trait AES128 extends SymmetricJavaBlockCipher[SymmetricKey128] { lazy val algo = "AES" }
sealed trait AES192 extends SymmetricJavaBlockCipher[SymmetricKey192] { lazy val algo = "AES" }
sealed trait AES256 extends SymmetricJavaBlockCipher[SymmetricKey256] { lazy val algo = "AES" }

object AES128 {
  implicit val builder = new CanBuildBlockCipher[AES128] {
    def build(params: Parameters): Try[AES128] = {
      Parameters.checkParam[SymmetricKey128](params, 'symmetricKey128) match {
        case Success(k) ⇒ Success(new AES128 { lazy val key = k })
        case Failure(f) ⇒ Failure(f)
      }
    }
  }
}

object AES192 {
  implicit val builder = new CanBuildBlockCipher[AES192] {
    def build(params: Parameters): Try[AES192] = {
      Parameters.checkParam[SymmetricKey192](params, 'symmetricKey192) match {
        case Success(k) ⇒ Success(new AES192 { lazy val key = k })
        case Failure(f) ⇒ Failure(f)
      }
    }
  }
}

object AES256 {
  implicit val builder = new CanBuildBlockCipher[AES256] {
    def build(params: Parameters): Try[AES256] = {
      Parameters.checkParam[SymmetricKey256](params, 'symmetricKey256) match {
        case Success(k) ⇒ Success(new AES256 { lazy val key = k })
        case Failure(f) ⇒ Failure(f)
      }
    }
  }
}
