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
package xyz.wiedenhoeft.scalacrypt

import org.scalatest._
import scala.util.{ Try, Success, Failure }

class RSASpec extends FlatSpec with Matchers {
  val testKey =
""" |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
    |5zIfjLTf4x6AEgvDsQltpLsCxSXGx4c5w4PfRQ==""".stripMargin.toBase64Bytes.toKey[RSAKey].get
  
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

  "RSA encryption" should "correctly encrypt and decrypt data" in {
    val suite = suites.RSA_ECB_OAEP(testKey, 16).get
    val test = (0 until 16) map { _.toByte }
    val c = suite.encrypt(test).get
    suite.decrypt(c).get should be (test)
  }

  it should "not fail on certain data inputs." in {
    val test = "AmzVJLEIo/6xoaqpZ6G5SutGJ8Rxh5Mk9mPhnuj+CBDnp+BE4jITQo1wtzFOLjQnwSp/nmK9zScDJoDsWYk9CA==".toBase64Bytes
    val rsa = new blockciphers.RSA { val key = testKey }
    rsa.decryptBlock(rsa.encryptBlock(test).get).get should be (test)
  }
}
