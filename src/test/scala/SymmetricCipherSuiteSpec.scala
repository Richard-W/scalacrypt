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

abstract class SymmetricCipherSuiteSpec[KeyType <: SymmetricKey](suite: SymmetricCipherSuite[KeyType], keyGen: () ⇒ KeyType) extends FlatSpec with Matchers {

  val name: String = suite.getClass.getName.split("\\.").last.split("\\$").last

  it should "reject invalid signatures." in {
    val key: KeyType = keyGen()

    val test1: Array[Byte] = "abcdefghijk".getBytes
    val cipher1: Array[Byte] = suite.encrypt(test1, key).toArray
    cipher1(5) = (cipher1(5).toInt + 1).toByte
    suite.decrypt(cipher1, key) match {
      case Success(t) ⇒
      fail("False signature did not get rejected.")

      case Failure(f) ⇒
    }
  }
}

class AES128HmacSHA1AuthSpec extends SymmetricCipherSuiteSpec(AES128HmacSHA1, () ⇒ { SymmetricKey.generate[SymmetricKey128]() })
class AES128HmacSHA256AuthSpec extends SymmetricCipherSuiteSpec(AES128HmacSHA256, () ⇒ { SymmetricKey.generate[SymmetricKey128]() })
class AES192HmacSHA1AuthSpec extends SymmetricCipherSuiteSpec(AES192HmacSHA1, () ⇒ { SymmetricKey.generate[SymmetricKey192]() })
class AES192HmacSHA256AuthSpec extends SymmetricCipherSuiteSpec(AES192HmacSHA256, () ⇒ { SymmetricKey.generate[SymmetricKey192]() })
class AES256HmacSHA1AuthSpec extends SymmetricCipherSuiteSpec(AES256HmacSHA1, () ⇒ { SymmetricKey.generate[SymmetricKey256]() })
class AES256HmacSHA256AuthSpec extends SymmetricCipherSuiteSpec(AES256HmacSHA256, () ⇒ { SymmetricKey.generate[SymmetricKey256]() })
