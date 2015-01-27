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
import khash._
import iteratees._

class KeyedHashSpec extends FlatSpec with Matchers {
  
  "HmacSha256" should "be consistent with the test vectors." in {
    val key1: Key = Seq[Byte](0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b).toKey[SymmetricKeyArbitrary].get
    val data1: Seq[Byte] = Seq(0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65) map { _.toByte }
    val hmac1: Seq[Byte] = Seq(0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7) map { _.toByte }
    val myMac1 = HmacSHA256(data1, key1)
    myMac1 should be (hmac1)
    HmacSHA256.verify(data1, hmac1, key1) should be (true)


    val key2: Key = Seq(0x4a, 0x65, 0x66, 0x65).map({ _.toByte }).toKey[SymmetricKeyArbitrary].get
    val data2: Seq[Byte] = Seq(0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20, 0x79, 0x61, 0x20, 0x77, 0x61, 0x6e, 0x74, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x3f) map { _.toByte }
    val hmac2: Seq[Byte] = Seq(0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43) map { _.toByte }
    val myMac2 = HmacSHA256(data2, key2)
    myMac2 should be (hmac2)
    HmacSHA256.verify(data2, hmac2, key2) should be (true)
  }

  it should "not fail on keys with length zero." in {
    HmacSHA256(Seq[Byte](1, 2, 3), Seq[Byte]().toKey[SymmetricKeyArbitrary].get)
  }

  it should "not fail on data with length zero." in {
    HmacSHA256(Seq(), Seq[Byte](1,2,3).toKey[SymmetricKeyArbitrary].get)
  }

  it should "have the same output for a zero key and an empty key" in {
    val k1 = Seq[Byte]().toKey[SymmetricKeyArbitrary].get
    val k2 = Seq[Byte](0, 0, 0, 0, 0).toKey[SymmetricKeyArbitrary].get
    val data = "abcdefg".getBytes
    val h1 = HmacSHA256(data, k1)
    val h2 = HmacSHA256(data, k2)
    h1 should be (h2)
  }

  it should "be able to process iterators without consuming them." in {
    val key = Key.generate[SymmetricKeyArbitrary]
    val seq = Seq(Seq(1,2,3), Seq(4,5,6), Seq(7,8,9)) map { _.map { _.toByte }}
    val data = seq.flatMap { e ⇒ e }

    val mac = HmacSHA256(data, key)
    var iteratee: Iteratee[Seq[Byte], Seq[Byte]] = null

    (HmacSHA256(seq.toIterator, key) map({ t ⇒
      iteratee = t._2
      t._1
    })).toSeq should be (seq)

    iteratee.run.get should be (mac)
  }

  "The iteratee of a KeyedHash" should "be branchable." in {
    val key = Key.generate[SymmetricKeyArbitrary]
    val base = HmacSHA256(key).fold(Element(Seq(1,2,3) map { _.toByte }))
    val branch1Result = base.fold(Element(Seq(4,5,6) map { _.toByte })).run.get
    val branch2Result = base.fold(Element(Seq(7,8,9) map { _.toByte })).run.get

    branch1Result should be (HmacSHA256(Seq(1,2,3,4,5,6) map { _.toByte }, key))
    branch2Result should be (HmacSHA256(Seq(1,2,3,7,8,9) map { _.toByte }, key))
  }
}
