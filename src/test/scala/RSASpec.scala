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

class RSASpec extends FlatSpec with Matchers {
  val testKey = Key.generate[RSAKey]
  
  "A generated RSAKey" should "be serializable." in {
    val bytes = testKey.bytes
    val newKey = bytes.toKey[RSAKey].get
    newKey should be (testKey)
  }

  it should "have length 512." in {
    testKey.length should be (512)
  }

  it should "export the public part." in {
    testKey.isPrivateKey should be (true)
    val pubKey = testKey.publicKey
    pubKey.isPrivateKey should be (false)
    pubKey.d should be (None)
    pubKey.p should be (None)
    pubKey.q should be (None)
  }

  "RSA encryption" should "correctly encrypt and decrypt keys" in {
    val suite = suites.RSA_ECB_OAEP(testKey, 16).get
    val test = (0 until 16) map { _.toByte }
    val c = suite.encrypt(test).get
    suite.decrypt(c).get should be (test)
  }
}
