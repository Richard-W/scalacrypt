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
import hash._

class HashSpec extends FlatSpec with Matchers {

  "The hashes" should "conform to the testvectors" in {
    val testbytes = "The quick brown fox jumps over the lazy dog".getBytes.toSeq
    val md5 = MD5(testbytes)
    val sha1 = SHA1(testbytes)
    val sha256 = SHA256(testbytes)

    md5 should be(Seq(0x9e, 0x10, 0x7d, 0x9d, 0x37, 0x2b, 0xb6, 0x82, 0x6b, 0xd8, 0x1d, 0x35, 0x42, 0xa4, 0x19, 0xd6) map { _.toByte })
    sha1 should be(Seq(0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84, 0x9e, 0xe1, 0xbb, 0x76, 0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12) map { _.toByte })
    sha256 should be(Seq(0xd7, 0xa8, 0xfb, 0xb3, 0x07, 0xd7, 0x80, 0x94, 0x69, 0xca, 0x9a, 0xbc, 0xb0, 0x08, 0x2e, 0x4f, 0x8d, 0x56, 0x51, 0xe4, 0x6d, 0x3c, 0xdb, 0x76, 0x2d, 0x02, 0xd0, 0xbf, 0x37, 0xc9, 0xe5, 0x92) map { _.toByte })
  }

  "The hash lengths" should "be right." in {
    MD5.length should be(16)
    SHA1.length should be(20)
    SHA256.length should be(32)
  }

  "Hashes" should "be able to process an iterator returning a future." in {
    val testbytes = "The quick brown fox jumps over the lazy dog".getBytes.toIterator.grouped(5)

    val (iterator, futureHash) = SHA256(testbytes)
    // Empty the iterator so the promise gets completed
    while (iterator.hasNext) iterator.next

    futureHash.isCompleted should be(true)
    futureHash.value.get.get should be(Seq(0xd7, 0xa8, 0xfb, 0xb3, 0x07, 0xd7, 0x80, 0x94, 0x69, 0xca, 0x9a, 0xbc, 0xb0, 0x08, 0x2e, 0x4f, 0x8d, 0x56, 0x51, 0xe4, 0x6d, 0x3c, 0xdb, 0x76, 0x2d, 0x02, 0xd0, 0xbf, 0x37, 0xc9, 0xe5, 0x92) map { _.toByte })
  }
}
