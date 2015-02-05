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
import blockciphers._

class ThreefishSpec extends FlatSpec with Matchers {
  val tf256 = new Threefish256 {
    val key = Key.generate[SymmetricKey256]
    val tweak = (1 to 16) map { _.toByte }
  }

  val tf512 = new Threefish512 {
    val key = Key.generate[SymmetricKey512]
    val tweak = (1 to 16) map { _.toByte }
  }

  val tf1024 = new Threefish1024 {
    val key = Key.generate[SymmetricKey1024]
    val tweak = (1 to 16) map { _.toByte }
  }

  "The Threefish mix function" should "be reversible." in {
    val tests = Seq[(Long, Long, Int)] (
      (5122421, 2141242, 53),
      (12, Long.MaxValue, 5),
      (Long.MaxValue, 5152124, 5),
      (Long.MaxValue, Long.MaxValue, 34)
    )
    for(test <- tests) {
      val mix = tf256.mix(test._1, test._2, test._3)
      val unmix = tf256.unmix(mix(0), mix(1), test._3)
      unmix(0) should be (test._1)
      unmix(1) should be (test._2)
    }
  }

  "The Threefish round application" should "be reversible." in {
    val test = Seq[Long](1, 2, 3, 4)
    val rots = Seq(52, 32, 67, 12)
    val key = Seq[Long](5, 6, 7, 8)

    tf256.unapplyRound(tf256.applyRound(test, rots, None), rots, None) should be (test)
    tf256.unapplyRound(tf256.applyRound(test, rots, Some(key)), rots, Some(key)) should be (test)
  }

  "Threefish256" should "use the correct reverse permutation." in {
    val test = (1 to 4) map { _.toLong }
    tf256.reversePermutate(tf256.permutate(test)) should be (test)
  }

  it should "correctly decrypt a previously encrypted block." in {
    val test = (1 to 32) map { _.toByte }
    tf256.decryptBlock(tf256.encryptBlock(test).get).get should be (test)
  }

  it should "conform to the testvectors." in {
    // Key, Tweak, Input, Output
    val tests = Seq[(Seq[Long], Seq[Long], Seq[Long], Seq[Long])](
      (
        Seq(0, 0, 0, 0),
        Seq(0, 0),
        Seq(0, 0, 0, 0),
        Seq(0x94EEEA8B1F2ADA84L, 0xADF103313EAE6670L, 0x952419A1F4B16D53L, 0xD83F13E63C9F6B11L)
      ), (
        Seq(0x1716151413121110L, 0x1F1E1D1C1B1A1918L, 0x2726252423222120L, 0x2F2E2D2C2B2A2928L),
        Seq(0x0706050403020100L, 0x0F0E0D0C0B0A0908L),
        Seq(0xF8F9FAFBFCFDFEFFL, 0xF0F1F2F3F4F5F6F7L, 0xE8E9EAEBECEDEEEFL, 0xE0E1E2E3E4E5E6E7L),
        Seq(0x277610F5036C2E1FL, 0x25FB2ADD1267773EL, 0x9E1D67B3E4B06872L, 0x3F76BC7651B39682L)
      )
    )

    for(test <- tests) {
      val tf = new Threefish256 {
        val key = tf256.words2block(test._1).toKey[SymmetricKey256].get
        val tweak = tf256.words2block(test._2)
      }
      tf.encryptBlock(tf.words2block(test._3)).get should be (tf.words2block(test._4))
      tf.decryptBlock(tf.words2block(test._4)).get should be (tf.words2block(test._3))
    }
  }

  "Threefish512" should "use the correct reverse permutation." in {
    val test = (1 to 8) map { _.toLong }
    tf512.reversePermutate(tf512.permutate(test)) should be (test)
  }

  it should "correctly decrypt a previously encrypted block." in {
    val test = (1 to 64) map { _.toByte }
    tf512.decryptBlock(tf512.encryptBlock(test).get).get should be (test)
  }

  it should "conform to the testvectors." in {
    // Key, Tweak, Input, Output
    val tests = Seq[(Seq[Long], Seq[Long], Seq[Long], Seq[Long])](
      (
        Seq(0, 0, 0, 0, 0, 0, 0, 0),
        Seq(0, 0),
        Seq(0, 0, 0, 0, 0, 0, 0, 0),
        Seq(0xBC2560EFC6BBA2B1L, 0xE3361F162238EB40L, 0xFB8631EE0ABBD175L, 0x7B9479D4C5479ED1L, 0xCFF0356E58F8C27BL, 0xB1B7B08430F0E7F7L, 0xE9A380A56139ABF1L, 0xBE7B6D4AA11EB47EL)
      ), (
        Seq(0x1716151413121110L, 0x1F1E1D1C1B1A1918L, 0x2726252423222120L, 0x2F2E2D2C2B2A2928L, 0x3736353433323130L, 0x3F3E3D3C3B3A3938L, 0x4746454443424140L, 0x4F4E4D4C4B4A4948L),
        Seq(0x0706050403020100L, 0x0F0E0D0C0B0A0908L),
        Seq(0xF8F9FAFBFCFDFEFFL, 0xF0F1F2F3F4F5F6F7L, 0xE8E9EAEBECEDEEEFL, 0xE0E1E2E3E4E5E6E7L, 0xD8D9DADBDCDDDEDFL, 0xD0D1D2D3D4D5D6D7L, 0xC8C9CACBCCCDCECFL, 0xC0C1C2C3C4C5C6C7L),
        Seq(0xD4A32EDD6ABEFA1CL, 0x6AD5C4252C3FF743L, 0x35AC875BE2DED68CL, 0x99A6C774EA5CD06CL, 0xDCEC9C4251D7F4F8L, 0xF5761BCB3EF592AFL, 0xFCABCB6A3212DF60L, 0xFD6EDE9FF9A2E14EL)
      )
    )

    for(test <- tests) {
      val tf = new Threefish512 {
        val key = tf512.words2block(test._1).toKey[SymmetricKey512].get
        val tweak = tf512.words2block(test._2)
      }
      tf.encryptBlock(tf.words2block(test._3)).get should be (tf.words2block(test._4))
      tf.decryptBlock(tf.words2block(test._4)).get should be (tf.words2block(test._3))
    }
  }

  "Threefish1024" should "use the correct reverse permutation." in {
    val test = (1 to 16) map { _.toLong }
    tf1024.reversePermutate(tf1024.permutate(test)) should be (test)
  }

  it should "correctly decrypt a previously encrypted block." in {
    val test = (1 to 128) map { _.toByte }
    tf1024.decryptBlock(tf1024.encryptBlock(test).get).get should be (test)
  }

  it should "conform to the testvectors." in {
    // Key, Tweak, Input, Output
    val tests = Seq[(Seq[Long], Seq[Long], Seq[Long], Seq[Long])](
      (
        Seq(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        Seq(0, 0),
        Seq(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        Seq(0x04B3053D0A3D5CF0L, 0x0136E0D1C7DD85F7L, 0x067B212F6EA78A5CL, 0x0DA9C10B4C54E1C6L, 0x0F4EC27394CBACF0L, 0x32437F0568EA4FD5L, 0xCFF56D1D7654B49CL, 0xA2D5FB14369B2E7BL, 0x540306B460472E0BL, 0x71C18254BCEA820DL, 0xC36B4068BEAF32C8L, 0xFA4329597A360095L, 0xC4A36C28434A5B9AL, 0xD54331444B1046CFL, 0xDF11834830B2A460L, 0x1E39E8DFE1F7EE4FL)
      ), (
        Seq(0x1716151413121110L, 0x1F1E1D1C1B1A1918L, 0x2726252423222120L, 0x2F2E2D2C2B2A2928L, 0x3736353433323130L, 0x3F3E3D3C3B3A3938L, 0x4746454443424140L, 0x4F4E4D4C4B4A4948L, 0x5756555453525150L, 0x5F5E5D5C5B5A5958L, 0x6766656463626160L, 0x6F6E6D6C6B6A6968L, 0x7776757473727170L, 0x7F7E7D7C7B7A7978L, 0x8786858483828180L, 0x8F8E8D8C8B8A8988L),
        Seq(0x0706050403020100L, 0x0F0E0D0C0B0A0908L),
        Seq(0xF8F9FAFBFCFDFEFFL, 0xF0F1F2F3F4F5F6F7L, 0xE8E9EAEBECEDEEEFL, 0xE0E1E2E3E4E5E6E7L, 0xD8D9DADBDCDDDEDFL, 0xD0D1D2D3D4D5D6D7L, 0xC8C9CACBCCCDCECFL, 0xC0C1C2C3C4C5C6C7L, 0xB8B9BABBBCBDBEBFL, 0xB0B1B2B3B4B5B6B7L, 0xA8A9AAABACADAEAFL, 0xA0A1A2A3A4A5A6A7L, 0x98999A9B9C9D9E9FL, 0x9091929394959697L, 0x88898A8B8C8D8E8FL, 0x8081828384858687L),
        Seq(0x483AC62C27B09B59L, 0x4CB85AA9E48221AAL, 0x80BC1644069F7D0BL, 0xFCB26748FF92B235L, 0xE83D70243B5D294BL, 0x316A3CA3587A0E02L, 0x5461FD7C8EF6C1B9L, 0x7DD5C1A4C98CA574L, 0xFDA694875AA31A35L, 0x03D1319C26C2624CL, 0xA2066D0DF2BF7827L, 0x6831CCDAA5C8A370L, 0x2B8FCD9189698DACL, 0xE47818BBFD604399L, 0xDF47E519CBCEA541L, 0x5EFD5FF4A5D4C259L)
      )
    )

    for(test <- tests) {
      val tf = new Threefish1024 {
        val key = tf1024.words2block(test._1).toKey[SymmetricKey1024].get
        val tweak = tf1024.words2block(test._2)
      }
      tf.encryptBlock(tf.words2block(test._3)).get should be (tf.words2block(test._4))
      tf.decryptBlock(tf.words2block(test._4)).get should be (tf.words2block(test._3))
    }
  }
}
