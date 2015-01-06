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
import padding._

class BlockPaddingSpec extends FlatSpec with Matchers {

  "PKCS7Padding" should "pad and unpad data correctly" in {
    val testvectors = Seq[(Int,Seq[Seq[Byte]],Seq[Seq[Byte]])](
      (
        16,
        Seq(Seq(1,2,3,4,5,6,7,8,9,10)),
        Seq(Seq(1,2,3,4,5,6,7,8,9,10,6,6,6,6,6,6))
      ), (
        16,
        Seq(Seq(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16)),
        Seq(Seq(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16), Seq(16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16))
      ), (
        16,
        Seq(Seq()),
        Seq(Seq(16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16))
      ), (
        8,
        Seq(Seq(1,2,3,4,5,6)),
        Seq(Seq(1,2,3,4,5,6,2,2))
      ), (
        8,
        Seq(Seq(1,2,3,4,5,6,7,8)),
        Seq(Seq(1,2,3,4,5,6,7,8), Seq(8,8,8,8,8,8,8,8))
      ), (
        8,
        Seq(Seq()),
        Seq(Seq(8,8,8,8,8,8,8,8))
      ), (
        16,
        Seq(Seq(1,2,3),Seq(4,5,6),Seq(7,8,9),Seq(10)),
        Seq(Seq(1,2,3,4,5,6,7,8,9,10,6,6,6,6,6,6))
      )
    )

    for(testvector <- testvectors) {
      val padding = new PKCS7Padding {
        def blockSize: Int = testvector._1
      }
      padding.pad(testvector._2.toIterator).toSeq should be (testvector._3)
      padding.unpad(testvector._3.toIterator).toSeq.map({ _.get }).flatten should be (testvector._2.flatten)
    }
  }

  it should "return an error when invalid padding is encountered" in {
    val tests = Seq[(Int,Seq[Seq[Byte]])] (
      (
        // Does not contain padding block
        8,
        Seq(Seq(1,2,3,4,5,6,7,8), Seq(1,2,3,4,5,6,7,8))
      ), (
        // Wrong padding byte
        8,
        Seq(Seq(1,2,3,4,5,6,3,3))
      ), (
        // Illegal block size
        8,
        Seq(Seq(1,2,3,4,5,6,7), Seq(1))
      ), (
        // Illegal block size
        8,
        Seq(Seq(1,2,3), Seq(8,8,8,8,8,8,8,8))
      ), (
        // Wrong byte inside padding
        8,
        Seq(Seq(1,2,6,6,6,7,6,6))
      )
    )

    for(test <- tests) {
      val padding = new PKCS7Padding {
        def blockSize: Int = test._1
      }
      try {
        padding.unpad(test._2.toIterator).toSeq.filter({ _.isFailure }).headOption shouldBe a [Some[_]]
      } catch { 
        case t: Throwable ⇒
        fail(t.getMessage + " :: " + test.toString)
      }
    }
  }
}
