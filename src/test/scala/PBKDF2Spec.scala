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
import misc._

class PBKDF2Spec extends FlatSpec with Matchers {
  
  "PBKDF2" should "be consistent with the test vectors." in {
    val p1 = SymmetricKey[SymmetricKeyArbitrary]("password".getBytes).get
    val s1 = "salt"
    val l1 = 20
    val i1 = 1
    val res11 = Seq(0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6) map { _.toByte }
    val res12 = PBKDF2HmacSHA1(p1, s1.getBytes, i1, l1)
    res11 should be (res12)

    val p2 = SymmetricKey[SymmetricKeyArbitrary]("password".getBytes).get
    val s2 = "salt"
    val l2 = 20
    val i2 = 2
    val res21 = Seq(0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57) map { _.toByte }
    val res22 = PBKDF2HmacSHA1(p2, s2.getBytes, i2, l2)
    res21 should be (res22)

    val p3 = SymmetricKey[SymmetricKeyArbitrary]("password".getBytes).get
    val s3 = "salt"
    val l3 = 20
    val i3 = 4096
    val res31 = Seq(0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a, 0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7, 0x21, 0xd0, 0x65, 0xa4, 0x29, 0xc1) map { _.toByte }
    val res32 = PBKDF2HmacSHA1(p3, s3.getBytes, i3, l3)
    res31 should be (res32)
    
    val p4 = SymmetricKey[SymmetricKeyArbitrary]("passwordPASSWORDpassword".getBytes).get
    val s4 = "saltSALTsaltSALTsaltSALTsaltSALTsalt"
    val l4 = 25
    val i4 = 4096
    val res41 = Seq(0x3d, 0x2e, 0xec, 0x4f, 0xe4, 0x1c, 0x84, 0x9b, 0x80, 0xc8, 0xd8, 0x36, 0x62, 0xc0, 0xe4, 0x4a, 0x8b, 0x29, 0x1a, 0x96, 0x4c, 0xf2, 0xf0, 0x70, 0x38) map { _.toByte }
    val res42 = PBKDF2HmacSHA1(p4, s4.getBytes, i4, l4)
    res41 should be (res42)

  }
}
