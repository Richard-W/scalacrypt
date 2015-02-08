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
  val params = Parameters(
    'symmetricKey256 -> Key.generate[SymmetricKey256],
    'symmetricKey512 -> Key.generate[SymmetricKey512],
    'symmetricKey1024 -> Key.generate[SymmetricKey1024],
    'tweak -> ((1 to 16) map { _.toByte })
  )

  val tf256 = BlockCipher[Threefish256](params).get
  val tf512 = BlockCipher[Threefish512](params).get
  val tf1024 = BlockCipher[Threefish1024](params).get

  // Key, Tweak, Input, Output
  val tests256 = Seq[(Seq[Long], Seq[Long], Seq[Long], Seq[Long])](
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

  val tests512 = Seq[(Seq[Long], Seq[Long], Seq[Long], Seq[Long])](
    (
      Seq(0, 0, 0, 0, 0, 0, 0, 0),
      Seq(0, 0),
      Seq(0, 0, 0, 0, 0, 0, 0, 0),
      Seq(0xBC2560EFC6BBA2B1L, 0xE3361F162238EB40L, 0xFB8631EE0ABBD175L, 0x7B9479D4C5479ED1L,
          0xCFF0356E58F8C27BL, 0xB1B7B08430F0E7F7L, 0xE9A380A56139ABF1L, 0xBE7B6D4AA11EB47EL)
    ), (
      Seq(0x1716151413121110L, 0x1F1E1D1C1B1A1918L, 0x2726252423222120L, 0x2F2E2D2C2B2A2928L,
          0x3736353433323130L, 0x3F3E3D3C3B3A3938L, 0x4746454443424140L, 0x4F4E4D4C4B4A4948L),
      Seq(0x0706050403020100L, 0x0F0E0D0C0B0A0908L),
      Seq(0xF8F9FAFBFCFDFEFFL, 0xF0F1F2F3F4F5F6F7L, 0xE8E9EAEBECEDEEEFL, 0xE0E1E2E3E4E5E6E7L,
          0xD8D9DADBDCDDDEDFL, 0xD0D1D2D3D4D5D6D7L, 0xC8C9CACBCCCDCECFL, 0xC0C1C2C3C4C5C6C7L),
      Seq(0xD4A32EDD6ABEFA1CL, 0x6AD5C4252C3FF743L, 0x35AC875BE2DED68CL, 0x99A6C774EA5CD06CL,
          0xDCEC9C4251D7F4F8L, 0xF5761BCB3EF592AFL, 0xFCABCB6A3212DF60L, 0xFD6EDE9FF9A2E14EL)
    )
  )

  val tests1024 = Seq[(Seq[Long], Seq[Long], Seq[Long], Seq[Long])](
    (
      Seq(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
      Seq(0, 0),
      Seq(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
      Seq(0x04B3053D0A3D5CF0L, 0x0136E0D1C7DD85F7L, 0x067B212F6EA78A5CL, 0x0DA9C10B4C54E1C6L,
          0x0F4EC27394CBACF0L, 0x32437F0568EA4FD5L, 0xCFF56D1D7654B49CL, 0xA2D5FB14369B2E7BL,
          0x540306B460472E0BL, 0x71C18254BCEA820DL, 0xC36B4068BEAF32C8L, 0xFA4329597A360095L,
          0xC4A36C28434A5B9AL, 0xD54331444B1046CFL, 0xDF11834830B2A460L, 0x1E39E8DFE1F7EE4FL)
    ), (
      Seq(0x1716151413121110L, 0x1F1E1D1C1B1A1918L, 0x2726252423222120L, 0x2F2E2D2C2B2A2928L,
          0x3736353433323130L, 0x3F3E3D3C3B3A3938L, 0x4746454443424140L, 0x4F4E4D4C4B4A4948L,
          0x5756555453525150L, 0x5F5E5D5C5B5A5958L, 0x6766656463626160L, 0x6F6E6D6C6B6A6968L,
          0x7776757473727170L, 0x7F7E7D7C7B7A7978L, 0x8786858483828180L, 0x8F8E8D8C8B8A8988L),
      Seq(0x0706050403020100L, 0x0F0E0D0C0B0A0908L),
      Seq(0xF8F9FAFBFCFDFEFFL, 0xF0F1F2F3F4F5F6F7L, 0xE8E9EAEBECEDEEEFL, 0xE0E1E2E3E4E5E6E7L,
          0xD8D9DADBDCDDDEDFL, 0xD0D1D2D3D4D5D6D7L, 0xC8C9CACBCCCDCECFL, 0xC0C1C2C3C4C5C6C7L,
          0xB8B9BABBBCBDBEBFL, 0xB0B1B2B3B4B5B6B7L, 0xA8A9AAABACADAEAFL, 0xA0A1A2A3A4A5A6A7L,
          0x98999A9B9C9D9E9FL, 0x9091929394959697L, 0x88898A8B8C8D8E8FL, 0x8081828384858687L),
      Seq(0x483AC62C27B09B59L, 0x4CB85AA9E48221AAL, 0x80BC1644069F7D0BL, 0xFCB26748FF92B235L,
          0xE83D70243B5D294BL, 0x316A3CA3587A0E02L, 0x5461FD7C8EF6C1B9L, 0x7DD5C1A4C98CA574L,
          0xFDA694875AA31A35L, 0x03D1319C26C2624CL, 0xA2066D0DF2BF7827L, 0x6831CCDAA5C8A370L,
          0x2B8FCD9189698DACL, 0xE47818BBFD604399L, 0xDF47E519CBCEA541L, 0x5EFD5FF4A5D4C259L)
    )
  )

  val test0Params = Parameters(
    'symmetricKey256 -> Threefish.words2block(tests256(0)._1).toKey[SymmetricKey256].get,
    'symmetricKey512 -> Threefish.words2block(tests512(0)._1).toKey[SymmetricKey512].get,
    'symmetricKey1024 -> Threefish.words2block(tests1024(0)._1).toKey[SymmetricKey1024].get,
    'tweak -> Threefish.words2block(tests256(0)._2)
  )

  val test1Params = Parameters(
    'symmetricKey256 -> Threefish.words2block(tests256(1)._1).toKey[SymmetricKey256].get,
    'symmetricKey512 -> Threefish.words2block(tests512(1)._1).toKey[SymmetricKey512].get,
    'symmetricKey1024 -> Threefish.words2block(tests1024(1)._1).toKey[SymmetricKey1024].get,
    'tweak -> Threefish.words2block(tests256(1)._2)
  )

  "The Threefish mix function" should "be reversible." in {
    val tests = Seq[(Long, Long, Int)] (
      (5122421, 2141242, 53),
      (12, Long.MaxValue, 5),
      (Long.MaxValue, 5152124, 5),
      (Long.MaxValue, Long.MaxValue, 34)
    )
    for(test <- tests) {
      val mix = Threefish.mix(test._1, test._2, test._3)
      val unmix = Threefish.unmix(mix(0), mix(1), test._3)
      unmix(0) should be (test._1)
      unmix(1) should be (test._2)
    }
  }

  it should "be consistent with the testvectors." in {
    val tests = Seq[(Seq[Byte], Seq[Byte], Int, Seq[Byte], Seq[Byte])](
      (
        Seq(0, 0, 0, 0, 0, 0, 0, 0) map { _.toByte },
        Seq(0, 0, 0, 0, 0, 0, 0, 0) map { _.toByte },
        0,
        Seq(0, 0, 0, 0, 0, 0, 0, 0) map { _.toByte },
        Seq(0, 0, 0, 0, 0, 0, 0, 0) map { _.toByte }
      ), (
        Seq(1, 0, 0, 0, 0, 0, 0, 0) map { _.toByte },
        Seq(1, 0, 0, 0, 0, 0, 0, 0) map { _.toByte },
        0,
        Seq(2, 0, 0, 0, 0, 0, 0, 0) map { _.toByte },
        Seq(3, 0, 0, 0, 0, 0, 0, 0) map { _.toByte } 
      ), (
        Seq(1, 0, 0, 0, 0, 0, 0, 0) map { _.toByte },
        Seq(1, 0, 0, 0, 0, 0, 0, 0) map { _.toByte },
        1,
        Seq(2, 0, 0, 0, 0, 0, 0, 0) map { _.toByte },
        Seq(0, 0, 0, 0, 0, 0, 0, 0) map { _.toByte }
      ), (
        Seq(232, 3, 0, 0, 0, 0, 0, 0) map { _.toByte },
        Seq(208, 7, 0, 0, 0, 0, 0, 0) map { _.toByte },
        5,
        Seq(184, 11, 0, 0, 0, 0, 0, 0) map { _.toByte },
        Seq(184, 241, 0, 0, 0, 0, 0, 0) map { _.toByte }
      ), (
        Seq(232, 3, 0, 0, 0, 0, 0, 0) map { _.toByte },
        Seq(208, 7, 0, 0, 0, 0, 0, 0) map { _.toByte },
        62,
        Seq(184, 11, 0, 0, 0, 0, 0, 0) map { _.toByte },
        Seq(76, 10, 0, 0, 0, 0, 0, 0) map { _.toByte }
      )
    )

    for(test <- tests) {
      val a = Threefish.bytes2word(test._1)
      val b = Threefish.bytes2word(test._2)
      val r = test._3
      val x = Threefish.bytes2word(test._4)
      val y = Threefish.bytes2word(test._5)

      Threefish.mix(a, b, r) should be (Seq(x, y))
    }
  }

  "The Threefish conversion between bytes and words" should "be reversible." in {
    Threefish.block2words(Threefish.words2block(tests256(1)._3)) should be (tests256(1)._3)
    Threefish.block2words(Threefish.words2block(tests256(1)._4)) should be (tests256(1)._4)
  }

  "Threefish256" should "correctly decrypt a previously encrypted block." in {
    val test = (1 to 32) map { _.toByte }
    tf256.decryptBlock(tf256.encryptBlock(test).get).get should be (test)
  }

  it should "have its key and tweak correctly initialized." in {
    val tf = BlockCipher[Threefish256](test1Params).get

    tf.keyWords.length should be (5)
    Threefish.words2block(tf.keyWords) should be (Seq(16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 34, 26, 252, 169, 218, 27, 209, 27) map { _.toByte })
    tf.keyWords.slice(0, tf.keyWords.length - 1) should be (tests256(1)._1)

    tf.tweakWords.length should be (3)
    Threefish.words2block(tf.tweakWords) should be (Seq(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 8, 8, 8, 8, 8, 8, 8, 8) map { _.toByte })
    tf.tweakWords.slice(0, 2) should be (tests256(1)._2)
  }

  it should "use the correct round keys." in {
    val tf = BlockCipher[Threefish256](test1Params).get

    val k = tf.keyWords
    val t = tf.tweakWords
    val rk = tf.roundKeys

    rk( 0) should be (Seq(k(0), k(1) + t(0), k(2) + t(1), k(3)))
    rk( 1) should be (Seq(k(1), k(2) + t(1), k(3) + t(2), k(4) +  1))
    rk( 2) should be (Seq(k(2), k(3) + t(2), k(4) + t(0), k(0) +  2))
    rk( 3) should be (Seq(k(3), k(4) + t(0), k(0) + t(1), k(1) +  3))
    rk( 4) should be (Seq(k(4), k(0) + t(1), k(1) + t(2), k(2) +  4))
    rk( 5) should be (Seq(k(0), k(1) + t(2), k(2) + t(0), k(3) +  5))
    rk( 6) should be (Seq(k(1), k(2) + t(0), k(3) + t(1), k(4) +  6))
    rk( 7) should be (Seq(k(2), k(3) + t(1), k(4) + t(2), k(0) +  7))
    rk( 8) should be (Seq(k(3), k(4) + t(2), k(0) + t(0), k(1) +  8))
    rk( 9) should be (Seq(k(4), k(0) + t(0), k(1) + t(1), k(2) +  9))
    rk(10) should be (Seq(k(0), k(1) + t(1), k(2) + t(2), k(3) + 10))
    rk(11) should be (Seq(k(1), k(2) + t(2), k(3) + t(0), k(4) + 11))
    rk(12) should be (Seq(k(2), k(3) + t(0), k(4) + t(1), k(0) + 12))
    rk(13) should be (Seq(k(3), k(4) + t(1), k(0) + t(2), k(1) + 13))
    rk(14) should be (Seq(k(4), k(0) + t(2), k(1) + t(0), k(2) + 14))
    rk(15) should be (Seq(k(0), k(1) + t(0), k(2) + t(1), k(3) + 15))
    rk(16) should be (Seq(k(1), k(2) + t(1), k(3) + t(2), k(4) + 16))
    rk(17) should be (Seq(k(2), k(3) + t(2), k(4) + t(0), k(0) + 17))
    rk(18) should be (Seq(k(3), k(4) + t(0), k(0) + t(1), k(1) + 18))


    Threefish.words2block(rk( 0)) should be (Seq(16, 17, 18, 19, 20, 21, 22, 23, 24, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 40, 41, 42, 43, 44, 45, 46, 47) map { _.toByte })
    Threefish.words2block(rk( 1)) should be (Seq(24, 25, 26, 27, 28, 29, 30, 31, 40, 42, 44, 46, 48, 50, 52, 54, 48, 49, 50, 51, 52, 53, 54, 55, 35, 26, 252, 169, 218, 27, 209, 27) map { _.toByte })
    Threefish.words2block(rk( 2)) should be (Seq(32, 33, 34, 35, 36, 37, 38, 39, 48, 49, 50, 51, 52, 53, 54, 55, 34, 27, 254, 172, 222, 32, 215, 34, 18, 17, 18, 19, 20, 21, 22, 23) map { _.toByte })
    Threefish.words2block(rk( 3)) should be (Seq(40, 41, 42, 43, 44, 45, 46, 47, 34, 27, 254, 172, 222, 32, 215, 34, 24, 26, 28, 30, 32, 34, 36, 38, 27, 25, 26, 27, 28, 29, 30, 31) map { _.toByte })
    Threefish.words2block(rk( 4)) should be (Seq(34, 26, 252, 169, 218, 27, 209, 27, 24, 26, 28, 30, 32, 34, 36, 38, 32, 33, 34, 35, 36, 37, 38, 39, 36, 33, 34, 35, 36, 37, 38, 39) map { _.toByte })
    Threefish.words2block(rk( 5)) should be (Seq(16, 17, 18, 19, 20, 21, 22, 23, 32, 33, 34, 35, 36, 37, 38, 39, 32, 34, 36, 38, 40, 42, 44, 46, 45, 41, 42, 43, 44, 45, 46, 47) map { _.toByte })
    Threefish.words2block(rk( 6)) should be (Seq(24, 25, 26, 27, 28, 29, 30, 31, 32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 40, 26, 252, 169, 218, 27, 209, 27) map { _.toByte })
    Threefish.words2block(rk( 7)) should be (Seq(32, 33, 34, 35, 36, 37, 38, 39, 48, 50, 52, 54, 56, 58, 60, 62, 42, 34, 4, 178, 226, 35, 217, 35, 23, 17, 18, 19, 20, 21, 22, 23) map { _.toByte })
    Threefish.words2block(rk( 8)) should be (Seq(40, 41, 42, 43, 44, 45, 46, 47, 42, 34, 4, 178, 226, 35, 217, 35, 16, 18, 20, 22, 24, 26, 28, 30, 32, 25, 26, 27, 28, 29, 30, 31) map { _.toByte })
    Threefish.words2block(rk( 9)) should be (Seq(34, 26, 252, 169, 218, 27, 209, 27, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46, 41, 33, 34, 35, 36, 37, 38, 39) map { _.toByte })
    Threefish.words2block(rk(10)) should be (Seq(16, 17, 18, 19, 20, 21, 22, 23, 32, 34, 36, 38, 40, 42, 44, 46, 40, 41, 42, 43, 44, 45, 46, 47, 50, 41, 42, 43, 44, 45, 46, 47) map { _.toByte })
    Threefish.words2block(rk(11)) should be (Seq(24, 25, 26, 27, 28, 29, 30, 31, 40, 41, 42, 43, 44, 45, 46, 47, 40, 42, 44, 46, 48, 50, 52, 54, 45, 26, 252, 169, 218, 27, 209, 27) map { _.toByte })
    Threefish.words2block(rk(12)) should be (Seq(32, 33, 34, 35, 36, 37, 38, 39, 40, 42, 44, 46, 48, 50, 52, 54, 42, 35, 6, 181, 230, 40, 223, 42, 28, 17, 18, 19, 20, 21, 22, 23) map { _.toByte })
    Threefish.words2block(rk(13)) should be (Seq(40, 41, 42, 43, 44, 45, 46, 47, 42, 35, 6, 181, 230, 40, 223, 42, 24, 25, 26, 27, 28, 29, 30, 31, 37, 25, 26, 27, 28, 29, 30, 31) map { _.toByte })
    Threefish.words2block(rk(14)) should be (Seq(34, 26, 252, 169, 218, 27, 209, 27, 24, 25, 26, 27, 28, 29, 30, 31, 24, 26, 28, 30, 32, 34, 36, 38, 46, 33, 34, 35, 36, 37, 38, 39) map { _.toByte })
    Threefish.words2block(rk(15)) should be (Seq(16, 17, 18, 19, 20, 21, 22, 23, 24, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 55, 41, 42, 43, 44, 45, 46, 47) map { _.toByte })
    Threefish.words2block(rk(16)) should be (Seq(24, 25, 26, 27, 28, 29, 30, 31, 40, 42, 44, 46, 48, 50, 52, 54, 48, 49, 50, 51, 52, 53, 54, 55, 50, 26, 252, 169, 218, 27, 209, 27) map { _.toByte })
    Threefish.words2block(rk(17)) should be (Seq(32, 33, 34, 35, 36, 37, 38, 39, 48, 49, 50, 51, 52, 53, 54, 55, 34, 27, 254, 172, 222, 32, 215, 34, 33, 17, 18, 19, 20, 21, 22, 23) map { _.toByte })
    Threefish.words2block(rk(18)) should be (Seq(40, 41, 42, 43, 44, 45, 46, 47, 34, 27, 254, 172, 222, 32, 215, 34, 24, 26, 28, 30, 32, 34, 36, 38, 42, 25, 26, 27, 28, 29, 30, 31) map { _.toByte })
  }

  it should "use the correct additional key and tweak word." in {
    val tf = BlockCipher[Threefish256](test1Params).get

    tf.keyWords.last should be (2004413935125273122L)
    tf.tweakWords.last should be (578721382704613384L)
  }

  it should "conform to the testvectors." in {
    val tf0 = BlockCipher[Threefish256](test0Params).get
    val c0 = Threefish.words2block(tests256(0)._4.zip(tests256(0)._3) map { t ⇒ t._1 ^ t._2 })
    tf0.encryptBlock(Threefish.words2block(tests256(0)._3)).get should be (c0)

    val tf1 = BlockCipher[Threefish256](test1Params).get
    val c1 = Threefish.words2block(tests256(1)._4.zip(tests256(1)._3) map { t ⇒ t._1 ^ t._2 })
    tf1.encryptBlock(Threefish.words2block(tests256(1)._3)).get should be (c1)
  }

  def testPermutation(a: Seq[Int], b: Seq[Int]) = {
    for(i <- (0 until a.length)) {
      a(b(i)) should be (i)
    }
  }

  it should "have the correct reverse permutation" in {
    val tf = BlockCipher[Threefish256](test1Params).get
    testPermutation(tf.permutation, tf.reversePermutation)
  }

  "Threefish512" should "correctly decrypt a previously encrypted block." in {
    val test = (1 to 64) map { _.toByte }
    tf512.decryptBlock(tf512.encryptBlock(test).get).get should be (test)
  }

  it should "conform to the testvectors." in {
    val tf0 = BlockCipher[Threefish512](test0Params).get
    val c0 = Threefish.words2block(tests512(0)._4.zip(tests512(0)._3) map { t ⇒ t._1 ^ t._2 })
    tf0.encryptBlock(Threefish.words2block(tests512(0)._3)).get should be (c0)

    val tf1 = BlockCipher[Threefish512](test1Params).get
    val c1 = Threefish.words2block(tests512(1)._4.zip(tests512(1)._3) map { t ⇒ t._1 ^ t._2 })
    tf1.encryptBlock(Threefish.words2block(tests512(1)._3)).get should be (c1)
  }

  it should "have the correct reverse permutation" in {
    val tf = BlockCipher[Threefish512](test1Params).get
    testPermutation(tf.permutation, tf.reversePermutation)
  }

  "Threefish1024" should "correctly decrypt a previously encrypted block." in {
    val test = (1 to 128) map { _.toByte }
    tf1024.decryptBlock(tf1024.encryptBlock(test).get).get should be (test)
  }

  it should "conform to the testvectors." in {
    val tf0 = BlockCipher[Threefish1024](test0Params).get
    val c0 = Threefish.words2block(tests1024(0)._4.zip(tests1024(0)._3) map { t ⇒ t._1 ^ t._2 })
    tf0.encryptBlock(Threefish.words2block(tests1024(0)._3)).get should be (c0)

    val tf1 = BlockCipher[Threefish1024](test1Params).get
    val c1 = Threefish.words2block(tests1024(1)._4.zip(tests1024(1)._3) map { t ⇒ t._1 ^ t._2 })
    tf1.encryptBlock(Threefish.words2block(tests1024(1)._3)).get should be (c1)
  }

  it should "have the correct reverse permutation" in {
    val tf = BlockCipher[Threefish256](test1Params).get
    testPermutation(tf.permutation, tf.reversePermutation)
  }

  "Threefish_CBC_256" should "decrypt a previously encrypted message." in {
    val message = (0 until 255) map { _.toByte }
    val suite = suites.Threefish256_CBC_PKCS7Padding(Key.generate[SymmetricKey256]).get
    val cipher = suite.encrypt(message).get

    suite.decrypt(cipher).get should be (message)
  }

  "Threefish_CBC_512" should "decrypt a previously encrypted message." in {
    val message = (0 until 255) map { _.toByte }
    val suite = suites.Threefish512_CBC_PKCS7Padding(Key.generate[SymmetricKey512]).get
    val cipher = suite.encrypt(message).get

    suite.decrypt(cipher).get should be (message)
  }

  "Threefish_CBC_1024" should "decrypt a previously encrypted message." in {
    val message = (0 until 255) map { _.toByte }
    val suite = suites.Threefish1024_CBC_PKCS7Padding(Key.generate[SymmetricKey1024]).get
    val cipher = suite.encrypt(message).get

    suite.decrypt(cipher).get should be (message)
  }
}
