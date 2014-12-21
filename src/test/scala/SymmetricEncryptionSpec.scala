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

abstract class SymmetricEncryptionSpec[KeyType <: SymmetricKey](enc: SymmetricEncryption[KeyType], keyGen: () ⇒ KeyType) extends FlatSpec with Matchers {

  val encryptionName: String = enc.getClass.getName.split("\\.").last.split("\\$").last

  encryptionName + " encryption" should "be able to en- and decipher." in {
    val key: KeyType = keyGen()

    val test1: Seq[Byte] = "abcdefghijk".getBytes
    val cipher1: Seq[Byte] = enc.encrypt(test1, key)
    val decipher1: Seq[Byte] = enc.decrypt(cipher1, key) match { case Success(s) ⇒ s; case Failure(f) ⇒ fail(f.getMessage) }
    test1 should be (decipher1)
  }

  it should "not reuse IVs." in {
    val key: KeyType = keyGen()

    val data: Seq[Byte] = "abcdefg".getBytes
    val c1 = enc.encrypt(data, key)
    val c2 = enc.encrypt(data, key)
    c1 should not be (c2)
    c1.slice(0,16) should not be (c2.slice(0,16))
  }

  it should "return failure on decrypting illegal data lengths." in {
    val key: KeyType = keyGen()

    enc.decrypt(Seq[Byte](), key) match {
      case Success(s) ⇒ fail("Did return success.")
      case Failure(f) ⇒
    }

    enc.decrypt(Seq(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47) map { _.toByte }, key) match {
      case Success(s) ⇒ fail("Did return success.")
      case Failure(f) ⇒
    }

    enc.decrypt(Seq(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16) map { _.toByte }, key) match {
      case Success(s) ⇒ fail("Did return success.")
      case Failure(f) ⇒
    }
  }
}

class AES128Spec extends SymmetricEncryptionSpec(AES128, () ⇒ { SymmetricKey128.generate })
class AES192Spec extends SymmetricEncryptionSpec(AES192, () ⇒ { SymmetricKey192.generate })
class AES256Spec extends SymmetricEncryptionSpec(AES256, () ⇒ { SymmetricKey256.generate })
