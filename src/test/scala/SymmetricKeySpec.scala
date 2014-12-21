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

class SymmetricKeySpec extends FlatSpec with Matchers {

  "A SymmetricKey" should "never have length 0." in {
    SymmetricKey(Seq()) shouldBe a [Failure[_]]
  }

  "A SymmetricKey128" should "always have length 16." in {
    SymmetricKey128(Seq(1,2,3) map { _.toByte }) shouldBe a [Failure[_]]
    SymmetricKey128(Seq(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16) map { _.toByte }) shouldBe a [Success[_]]
  }

  "A SymmetricKey192" should "always have length 24." in {
    SymmetricKey192(Seq(1,2,3) map { _.toByte }) shouldBe a [Failure[_]]
    SymmetricKey192(Seq(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24) map { _.toByte }) shouldBe a [Success[_]]
  }

  "A SymmetricKey256" should "always have length 32." in {
    SymmetricKey256(Seq(1,2,3) map { _.toByte }) shouldBe a [Failure[_]]
    SymmetricKey256(Seq(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32) map { _.toByte }) shouldBe a [Success[_]]
  }
}
