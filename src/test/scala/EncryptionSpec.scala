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

class EncryptionSpec extends FlatSpec with Matchers {

  "AES256 encryption" should "be able to en- and decipher." in {
    val key: Key = Key(Random.nextBytes(32))

    val test1: Seq[Byte] = "abcdefghijk".getBytes
    val cipher1: Seq[Byte] = AES256.encrypt(test1, key)
    val decipher1: Seq[Byte] = AES256.decrypt(cipher1, key)
    test1 should be (decipher1)
  }

  it should "not reuse IVs." in {
    val key: Key = Key(Random.nextBytes(32))

    val data: Seq[Byte] = "abcdefg".getBytes
    val c1 = AES256.encrypt(data, key)
    val c2 = AES256.encrypt(data, key)
    c1 should not be (c2)
    c1.slice(0,16) should not be (c2.slice(0,16))
  }

  it should "throw on illegal key lengths." in {
    val key1: Key = Key(Random.nextBytes(0))
    val key2: Key = Key(Random.nextBytes(16))
    val key3: Key = Key(Random.nextBytes(35))

    try {
      AES256.encrypt(Seq[Byte](1,2,3,4,5), key1)
      fail("Did not throw")
    } catch {
      case f: EncryptionException ⇒
      case t: Throwable ⇒
      t.printStackTrace
      fail("Wrong exception type.")
    }

    try {
      AES256.encrypt(Seq[Byte](1,2,3,4,5), key2)
      fail("Did not throw")
    } catch {
      case f: EncryptionException ⇒
      case _: Throwable ⇒
      fail("Wrong exception type.")
    }

    try {
      AES256.encrypt(Seq[Byte](1,2,3,4,5), key3)
      fail("Did not throw")
    } catch {
      case f: EncryptionException ⇒
      case _: Throwable ⇒
      fail("Wrong exception type.")
    }
  }

  it should "throw on illegal data lengths." in {
    val key: Key = Key(Random.nextBytes(32))

    try {
      AES256.decrypt(Seq[Byte](), key)
      fail("Did not throw")
    } catch {
      case f: EncryptionException ⇒
      case _: Throwable ⇒
      fail("Wrong exception type.")
    }

    try {
      AES256.decrypt(Seq(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47) map { _.toByte }, key)
      fail("Did not throw")
    } catch {
      case f: EncryptionException ⇒
      case _: Throwable ⇒
      fail("Wrong exception type.")
    }

    try {
      AES256.decrypt(Seq(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16) map { _.toByte }, key)
      fail("Did not throw")
    } catch {
      case f: EncryptionException ⇒
      case _: Throwable ⇒
      fail("Wrong exception type.")
    }
  }
}
