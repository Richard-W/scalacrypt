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

import scala.util.{ Try, Success, Failure }
import play.api.libs.iteratee._
import scala.concurrent.Await
import scala.concurrent.ExecutionContext
import scala.concurrent.duration._
import scala.concurrent.ExecutionContext.Implicits.global

/** Provides authenticated encryption using an encryption
  * algorithm and a MAC as delegates.
  *
  * A cipher suite encrypts data using the supplied encryption
  * mechanism and signs the result using the supplied MAC and
  * the encryption key.
  *
  * The MAC is appended to the output of the encryption.
  */
class SymmetricCipherSuite[KeyType <: SymmetricKey](val encryption: SymmetricEncryption[KeyType], val mac: Mac) extends SymmetricEncryption[KeyType] {

  /** Encrypts and signs data. */
  def encrypt(data: Iterator[Seq[Byte]], key: KeyType): Iterator[Seq[Byte]] = {
    new Iterator[Seq[Byte]] {

      val encryptionIterator: Iterator[Seq[Byte]] = encryption.encrypt(data, key)

      var macIteratee = mac(key)

      def hasNext: Boolean = encryptionIterator.hasNext

      def next: Seq[Byte] = {
        if(hasNext) {
          val chunk = encryptionIterator.next
          macIteratee = Await.result(macIteratee.feed(Input.El(chunk)), Duration.Inf)
          if(hasNext) {
            chunk
          } else {
            val mac = Await.result(macIteratee.run, Duration.Inf)
            chunk ++ mac
          }
        } else {
          Seq()
        }
      }
    }
  }

  /** Checks the signature and decrypts data. */
  def decrypt(data: Iterator[Seq[Byte]], key: KeyType): Iterator[Try[Seq[Byte]]] = {
    var buffer: Seq[Byte] = Seq()
    while(buffer.length < mac.length) {
      if(data.hasNext) {
        buffer = buffer ++ data.next
      } else {
        return Iterator(Failure(new SymmetricCipherSuiteException("Suite: Illegal data length.")))
      }
    }

    var macIteratee = mac(key)

    val dataIterator = new Iterator[Seq[Byte]] {

      var finished = false

      def hasNext: Boolean = !finished

      def next: Seq[Byte] = {
        if(hasNext) {
          if(data.hasNext) {
            buffer = buffer ++ data.next
          } else {
            finished = true
          }
          val rv = buffer.slice(0, buffer.length - mac.length)
          buffer = buffer.slice(buffer.length - mac.length, buffer.length)
          macIteratee = Await.result(macIteratee.feed(Input.El(rv)), Duration.Inf)
          rv
        } else {
          Seq()
        }
      }
    }

    val decryptIterator = encryption.decrypt(dataIterator, key)

    new Iterator[Try[Seq[Byte]]] {

      def hasNext: Boolean = decryptIterator.hasNext

      def next: Try[Seq[Byte]] = {
        if(hasNext) {
          val chunk = decryptIterator.next
          if(hasNext) {
            chunk
          } else {
            val mac: Seq[Byte] = Await.result(macIteratee.run, Duration.Inf)
            if(mac == buffer) {
              chunk
            } else {
              Failure(new SymmetricCipherSuiteException("Invalid MAC."))
            }
          }
        } else {
          Success(Seq())
        }
      }
    }
  }
}

/** Exception that is returned inside a Failure when something went wrong in
  * a CipherSuite
  */
class SymmetricCipherSuiteException(message: String) extends Exception(message)

/** Cipher suite using AES with a key length of 128 bit and HMAC SHA1 as
  * authentication.
  */
object AES128HmacSHA1 extends SymmetricCipherSuite(AES128, HmacSHA1)

/** Cipher suite using AES with a key length of 128 bit and HMAC SHA256 as
  * authentication.
  */
object AES128HmacSHA256 extends SymmetricCipherSuite(AES128, HmacSHA256)

/** Cipher suite using AES with a key length of 192 bit and HMAC SHA1 as
  * authentication.
  */
object AES192HmacSHA1 extends SymmetricCipherSuite(AES192, HmacSHA1)

/** Cipher suite using AES with a key length of 192 bit and HMAC SHA256 as
  * authentication.
  */
object AES192HmacSHA256 extends SymmetricCipherSuite(AES192, HmacSHA256)

/** Cipher suite using AES with a key length of 256 bit and HMAC SHA1 as
  * authentication.
  */
object AES256HmacSHA1 extends SymmetricCipherSuite(AES256, HmacSHA1)

/** Cipher suite using AES with a key length of 256 bit and HMAC SHA256 as
  * authentication.
  */
object AES256HmacSHA256 extends SymmetricCipherSuite(AES256, HmacSHA256)
