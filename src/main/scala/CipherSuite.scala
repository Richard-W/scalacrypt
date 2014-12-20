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
  */
class CipherSuite(encryption: Encryption, mac: Mac, key: Key) {

  /** Encrypts and signs data. */
  def encrypt(data: Seq[Byte]): Seq[Byte] = {
    val ctext: Seq[Byte] = encryption.encrypt(data, key)
    val signature: Seq[Byte] = mac(ctext, key)

    signature ++ ctext
  }

  /** Checks the signature and decrypts data. */
  def decrypt(data: Seq[Byte]): Try[Seq[Byte]] = {
    if(data.length < mac.length + 1) {
      return Failure(new Exception("Invalid length"))
    }

    val signature: Seq[Byte] = data.slice(0, mac.length)
    val ctext: Seq[Byte] = data.slice(mac.length, data.length)

    val myMac: Seq[Byte] = mac(ctext, key)
    if(myMac != signature) {
      return Failure(new Exception("Invalid MAC"))
    }

    Success(encryption.decrypt(ctext, key))
  }
}

/** Cipher suite using AES with a key length of 256 bit and HMAC SHA256 as
  * authentication.
  */
class AES256HmacSHA256(key: Key) extends CipherSuite(AES256, HmacSHA256, key)
