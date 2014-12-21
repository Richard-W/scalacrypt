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

import org.scalatest._
import scala.util.{ Try, Success, Failure }

class CipherSuiteSpec extends FlatSpec with Matchers {

  "A CipherSuite" should "encrypt and decrypt data." in {
    val key: SymmetricKey = SymmetricKey(Random.nextBytes(32))

    val test1: Array[Byte] = "abcdefghijk".getBytes
    val cipher1: Seq[Byte] = AES256HmacSHA256.encrypt(test1, key)
    val decipher1: Seq[Byte] = AES256HmacSHA256.decrypt(cipher1, key) match {
      case Success(t) ⇒
      t

      case Failure(f) ⇒
      fail(f.getMessage)
    }
    test1 should be (decipher1)
  }

  it should "reject invalid signatures." in {
    val key: SymmetricKey = SymmetricKey(Random.nextBytes(32))

    val test1: Array[Byte] = "abcdefghijk".getBytes
    val cipher1: Array[Byte] = AES256HmacSHA256.encrypt(test1, key).toArray
    cipher1(5) = (cipher1(5).toInt + 1).toByte
    AES256HmacSHA256.decrypt(cipher1, key) match {
      case Success(t) ⇒
      fail("False signature did not get rejected.")

      case Failure(f) ⇒
    }
  }
}
