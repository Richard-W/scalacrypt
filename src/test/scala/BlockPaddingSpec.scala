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

class BlockPaddingSpec extends FlatSpec with Matchers {

  "PKCS5Padding" should "wrap and unwrap data correctly" in {
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
      PKCS5Padding.wrap(testvector._2.toIterator, testvector._1).toSeq should be (testvector._3)
      PKCS5Padding.unwrap(testvector._3.toIterator).toSeq.map({ _.get }).flatten should be (testvector._2.flatten)
    }
  }
}
