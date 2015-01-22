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
import blockciphers.{ AES128, AES192, AES256 }

class SymmetricBlockCipherSpec extends FlatSpec with Matchers {

  "AES128" should "conform to the test vectors." in {
    val cipher: AES128 = new AES128 {
      def key = (Seq(
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
      ) map { _.toByte }).toKey[SymmetricKey128].get
    }
    def encrypt(block: Seq[Byte]): Seq[Byte] = cipher.encryptBlock(block).get
    def decrypt(block: Seq[Byte]): Seq[Byte] = cipher.decryptBlock(block).get

    var p = Seq(0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a) map { _.toByte }
    var c = Seq(0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97) map { _.toByte }
    encrypt(p) should be (c)
    decrypt(c) should be (p)

    p = Seq(0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51) map { _.toByte }
    c = Seq(0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d, 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf) map { _.toByte }
    encrypt(p) should be (c)
    decrypt(c) should be (p)

    p = Seq(0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef) map { _.toByte }
    c = Seq(0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23, 0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88) map { _.toByte }
    encrypt(p) should be (c)
    decrypt(c) should be (p)

    p = Seq(0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10) map { _.toByte }
    c = Seq(0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4) map { _.toByte }
    encrypt(p) should be (c)
    decrypt(c) should be (p)
  }

  it should "return IllegalBlockSizeException on illegal block sizes." in {
    val cipher: AES128 = new AES128 {
      def key = Key.generate[SymmetricKey128]
    }
    def encrypt(block: Seq[Byte]): Try[Seq[Byte]] = cipher.encryptBlock(block)
    def decrypt(block: Seq[Byte]): Try[Seq[Byte]] = cipher.decryptBlock(block)

    encrypt(Seq(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16) map { _.toByte }) shouldBe a [Success[_]]
    encrypt(Seq(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15) map { _.toByte }) shouldBe a [Failure[_]]
    encrypt(Seq(1) map { _.toByte }) shouldBe a [Failure[_]]
    encrypt(Seq[Byte]()) shouldBe a [Failure[_]]

    decrypt(Seq(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16) map { _.toByte }) shouldBe a [Success[_]]
    decrypt(Seq(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15) map { _.toByte }) shouldBe a [Failure[_]]
    decrypt(Seq(1) map { _.toByte }) shouldBe a [Failure[_]]
    decrypt(Seq[Byte]()) shouldBe a [Failure[_]]
  }

  "All AES objects" should "yield the correct block size." in {
    new AES128 { def key = Key.generate[SymmetricKey128] }.blockSize should be (16)
    new AES128 { def key = Key.generate[SymmetricKey128] }.blockSize should be (16)
    new AES128 { def key = Key.generate[SymmetricKey128] }.blockSize should be (16)
  }
}
