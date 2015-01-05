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
trait SymmetricEncryption[KeyType <: SymmetricKey] {

  /** Encrypts an iterator with a given key. */
  def encrypt(data: Iterator[Seq[Byte]], key: KeyType): Iterator[Seq[Byte]]

  /** Encrypts data with a given key. */
  def encrypt(data: Seq[Byte], key: KeyType): Seq[Byte] = encrypt(Iterator(data), key).fold(Seq[Byte]()) { (a, b) ⇒
    a ++ b
  }

  /** Decrypts an iterator with a given key. */
  def decrypt(data: Iterator[Seq[Byte]], key: KeyType): Iterator[Try[Seq[Byte]]]

  /** Decrypts data using a given key. */
  def decrypt(data: Seq[Byte], key: KeyType): Try[Seq[Byte]] = decrypt(Iterator(data), key).fold(Success(Seq[Byte]()))
  { (a, b) ⇒
    if(a.isFailure) {
      a
    } else if(b.isFailure) {
      b
    } else {
      Success(a.get ++ b.get)
    }
  }
}

sealed class AESEncryption[KeyType <: SymmetricKey](keyLength: Int) extends SymmetricEncryption[KeyType] {
  def encrypt(data: Iterator[Seq[Byte]], key: KeyType): Iterator[Seq[Byte]] = {
    val c: Cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    val k: java.security.Key = new SecretKeySpec(key.bytes.toArray, "AES")

    c.init(Cipher.ENCRYPT_MODE, k)
    val iv: Seq[Byte] = c.getIV

    Iterator(iv) ++ new Iterator[Seq[Byte]] {
      def hasNext: Boolean = data.hasNext

      def next: Seq[Byte] = {
        if(data.hasNext) {
          val chunk = data.next
          val decryptedChunk = if(data.hasNext) {
            c.update(chunk.toArray)
          } else {
            c.doFinal(chunk.toArray)
          }
          if(decryptedChunk != null) {
            decryptedChunk
          } else {
            Seq()
          }
        } else {
          Seq()
        }
      }
    }
  }

  def decrypt(data: Iterator[Seq[Byte]], key: KeyType): Iterator[Try[Seq[Byte]]] = {
    val c: Cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    val k: java.security.Key = new SecretKeySpec(key.bytes.toArray, "AES")

    var ivseq: Seq[Byte] = Seq()
    while(ivseq.length < 16) {
      if(data.hasNext) {
        ivseq = ivseq ++ data.next
      } else {
        return Iterator(Failure(new InvalidCiphertextException("Data was shorter than 16 bytes. Could not get IV.")))
      }
    }

    val iv: Seq[Byte] = ivseq.slice(0, 16)
    val ctext: Iterator[Seq[Byte]] = Iterator[Seq[Byte]](ivseq.slice(16, ivseq.length)) ++ data
    val ivspec: IvParameterSpec = new IvParameterSpec(iv.toArray)

    c.init(Cipher.DECRYPT_MODE, k, ivspec)
    
    new Iterator[Try[Seq[Byte]]] {
      def hasNext: Boolean = ctext.hasNext

      def next: Try[Seq[Byte]] = {
        if(ctext.hasNext) {
          val chunk = ctext.next
          if(ctext.hasNext) {
            val decryptedChunk = c.update(chunk.toArray)
            if(decryptedChunk != null) {
              Success(decryptedChunk)
            } else {
              Success(Seq())
            }
          } else {
            try {
              val decryptedChunk = c.doFinal(chunk.toArray)
              if(decryptedChunk != null) {
                Success(decryptedChunk)
              } else {
                Success(Seq())
              }
            } catch {
              case _: IllegalBlockSizeException ⇒
              Failure(new InvalidCiphertextException("Illegal data length. Data length must be divisible by 16."))

              case _: javax.crypto.BadPaddingException ⇒
              Failure(new DecryptionException("Bad padding. After decryption no PKCS5 padding was found. This could indicate a wrong key."))

              case t: Throwable ⇒
              // Should never happen.
              throw t
            }
          }
        } else {
          Success(Seq())
        }
      }
    }
  }
}

/** AES/CBC with a key length of 128 bits. */
object AES128 extends AESEncryption[SymmetricKey128](128 / 8)

/** AES/CBC with a key length of 192 bits. */
object AES192 extends AESEncryption[SymmetricKey192](192 / 8)

/** AES/CBC with a key length of 256 bits. */
object AES256 extends AESEncryption[SymmetricKey256](256 / 8)
