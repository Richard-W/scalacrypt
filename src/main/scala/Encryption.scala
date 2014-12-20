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
package xyz.wiedenhoeft.scalacrypt

import javax.crypto._
import javax.crypto.spec.SecretKeySpec
import javax.crypto.spec.IvParameterSpec
import scala.util.{ Try, Success, Failure }

/** Base trait for symmetric ciphers. */
trait Encryption {

  /** Encrypts data with a given key. */
  def encrypt(data: Seq[Byte], key: Key): Seq[Byte]

  /** Decrypts data using a given key. */
  def decrypt(data: Seq[Byte], key: Key): Seq[Byte]
}

/** Exception that gets thrown when encryption fails somehow. */
class EncryptionException(message: String) extends Exception(message)

/** Base class for AES encryptions. */
sealed class AESEncryption(keyLength: Int) extends Encryption {
  def encrypt(data: Seq[Byte], key: Key): Seq[Byte] = {
    if(key.length != keyLength) {
      throw new EncryptionException("Illegal key length")
    }

    val c: Cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    val k: java.security.Key = new SecretKeySpec(key.bytes.toArray, "AES")

    c.init(Cipher.ENCRYPT_MODE, k)

    val ctext: Seq[Byte] = c.doFinal(data.toArray)
    val iv: Seq[Byte] = c.getIV

    iv ++ ctext
  }

  def decrypt(data: Seq[Byte], key: Key): Seq[Byte] = {
    if(key.length != keyLength) {
      throw new EncryptionException("Illegal key length")
    }

    if(data.length < 32 || (data.length % 16) != 0) {
      // Data should be 128 bit IV and n 128 bit blocks.
      throw new EncryptionException("Illegal data length")
    }

    val c: Cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    val k: java.security.Key = new SecretKeySpec(key.bytes.toArray, "AES")

    val iv: Seq[Byte] = data.slice(0, 16)
    val ctext: Seq[Byte] = data.slice(16, data.length)
    val ivspec: IvParameterSpec = new IvParameterSpec(iv.toArray)

    c.init(Cipher.DECRYPT_MODE, k, ivspec)
    c.doFinal(ctext.toArray)
  }
}

/** AES/CBC with a key length of 128 bits. */
object AES128 extends AESEncryption(128 / 8)

/** AES/CBC with a key length of 256 bits. */
object AES256 extends AESEncryption(256 / 8)
