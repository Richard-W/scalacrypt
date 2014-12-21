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

/** Provides authenticated encryption using an encryption
  * algorithm and a MAC as delegates.
  *
  * A cipher suite encrypts data using the supplied encryption
  * mechanism and signs the result using the supplied MAC and
  * the encryption key.
  *
  * The MAC is prepended to the output of the encryption.
  */
class SymmetricCipherSuite[KeyType <: SymmetricKey](val encryption: SymmetricEncryption[KeyType], val mac: Mac) {

  /** Encrypts and signs data. */
  def encrypt(data: Seq[Byte], key: KeyType): Seq[Byte] = {
    val ctext: Seq[Byte] = encryption.encrypt(data, key)
    val signature: Seq[Byte] = mac(ctext, key)

    signature ++ ctext
  }

  /** Checks the signature and decrypts data. Only returns a
    * Success if the signature is valid.
    */
  def decrypt(data: Seq[Byte], key: KeyType): Try[Seq[Byte]] = {
    if(data.length < mac.length) {
      return Failure(new SymmetricCipherSuiteException("Invalid length"))
    }

    val signature: Seq[Byte] = data.slice(0, mac.length)
    val ctext: Seq[Byte] = data.slice(mac.length, data.length)

    val myMac: Seq[Byte] = mac(ctext, key)
    if(myMac != signature) {
      return Failure(new SymmetricCipherSuiteException("Invalid MAC"))
    }

    encryption.decrypt(ctext, key)
  }
}

/** Exception that is returned inside a Failure when something went wrong in
  * a CipherSuite
  */
class SymmetricCipherSuiteException(message: String) extends Exception

/** Cipher suite using AES with a key length of 128 bit and HMAC SHA1 as
  * authentication.
  */
object AES128HmacSHA1 extends SymmetricCipherSuite(AES128, HmacSHA1)

/** Cipher suite using AES with a key length of 128 bit and HMAC SHA256 as
  * authentication.
  */
object AES128HmacSHA256 extends SymmetricCipherSuite(AES128, HmacSHA256)

/** Cipher suite using AES with a key length of 256 bit and HMAC SHA1 as
  * authentication.
  */
object AES256HmacSHA1 extends SymmetricCipherSuite(AES256, HmacSHA1)

/** Cipher suite using AES with a key length of 256 bit and HMAC SHA256 as
  * authentication.
  */
object AES256HmacSHA256 extends SymmetricCipherSuite(AES256, HmacSHA256)
