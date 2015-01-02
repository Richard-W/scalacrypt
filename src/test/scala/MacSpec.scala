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

class MacSpec extends FlatSpec with Matchers {
  
  "HmacSha256" should "be consistent with the test vectors." in {
    val key1: SymmetricKey = SymmetricKey[SymmetricKeyArbitrary](Seq(0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b) map { _.toByte }).get
    val data1: Seq[Byte] = Seq(0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65) map { _.toByte }
    val hmac1: Seq[Byte] = Seq(0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7) map { _.toByte }
    val myMac1 = HmacSHA256(data1, key1)
    myMac1 should be (hmac1)


    val key2: SymmetricKey = SymmetricKey[SymmetricKeyArbitrary](Seq(0x4a, 0x65, 0x66, 0x65) map { _.toByte }).get
    val data2: Seq[Byte] = Seq(0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20, 0x79, 0x61, 0x20, 0x77, 0x61, 0x6e, 0x74, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x3f) map { _.toByte }
    val hmac2: Seq[Byte] = Seq(0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43) map { _.toByte }
    val myMac2 = HmacSHA256(data2, key2)
    myMac2 should be (hmac2)
  }

  it should "not fail on keys with length zero." in {
    HmacSHA256(Seq(1, 2, 3) map { _.toByte }, SymmetricKey[SymmetricKeyArbitrary](Seq[Byte]()).get)
  }

  it should "not fail on data with length zero." in {
    HmacSHA256(Seq(), SymmetricKey[SymmetricKeyArbitrary](Seq(1,2,3) map { _.toByte }).get)
  }

  it should "have the same output for a zero key and an empty key" in {
    val k1 = SymmetricKey[SymmetricKeyArbitrary](Seq()).get
    val k2 = SymmetricKey[SymmetricKeyArbitrary](Seq(0, 0, 0, 0, 0) map { _.toByte }).get
    val data = "abcdefg".getBytes
    val h1 = HmacSHA256(data, k1)
    val h2 = HmacSHA256(data, k2)
    h1 should be (h2)
  }
}
