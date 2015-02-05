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

  "Threefish512" should "use the correct reverse permutation." in {
    val test = (1 to 8) map { _.toLong }
    tf512.reversePermutate(tf512.permutate(test)) should be (test)
  }

  it should "correctly decrypt a previously encrypted block." in {
    val test = (1 to 64) map { _.toByte }
    tf512.decryptBlock(tf512.encryptBlock(test).get).get should be (test)
  }

  "Threefish1024" should "use the correct reverse permutation." in {
    val test = (1 to 16) map { _.toLong }
    tf1024.reversePermutate(tf1024.permutate(test)) should be (test)
  }

  it should "correctly decrypt a previously encrypted block." in {
    val test = (1 to 128) map { _.toByte }
    tf1024.decryptBlock(tf1024.encryptBlock(test).get).get should be (test)
  }
}
