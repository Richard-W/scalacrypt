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
package xyz.wiedenhoeft.scalacrypt.blockcipher

import xyz.wiedenhoeft.scalacrypt._
import scala.util.{ Try, Success, Failure }
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import java.security.Key

/** Base class for symmetric block ciphers that are implemented in the java crypto API. */
class SymmetricJavaBlockCipher[KeyType <: SymmetricKey](algo: String) extends SymmetricBlockCipher[KeyType] {

  val blockSize: Int = Cipher.getInstance(algo + "/ECB/NoPadding").getBlockSize

  private def crypt(key: KeyType, encrypt: Boolean): Seq[Byte] ⇒ Try[Seq[Byte]] = {
    val cipher: Cipher = Cipher.getInstance(algo + "/ECB/NoPadding")
    val secretKey: Key = new SecretKeySpec(key.bytes.toArray, "AES")
    if(encrypt) {
      cipher.init(Cipher.ENCRYPT_MODE, secretKey)
    } else {
      cipher.init(Cipher.DECRYPT_MODE, secretKey)
    }

    (block: Seq[Byte]) ⇒ {
      if(block.length != blockSize) {
        Failure(
          new IllegalBlockSizeException("Expected block of length " + blockSize + ", got " + block.length + " bytes.")
        )
      } else {
        // Exceptions this method throws should never happen.
        Success(cipher.doFinal(block.toArray))
      }
    }
  }

  def encrypt(key: KeyType): Seq[Byte] ⇒ Try[Seq[Byte]] = crypt(key, true)

  def decrypt(key: KeyType): Seq[Byte] ⇒ Try[Seq[Byte]] = crypt(key, false)
}

object AES128 extends SymmetricJavaBlockCipher[SymmetricKey128]("AES")
object AES192 extends SymmetricJavaBlockCipher[SymmetricKey192]("AES")
object AES256 extends SymmetricJavaBlockCipher[SymmetricKey256]("AES")
