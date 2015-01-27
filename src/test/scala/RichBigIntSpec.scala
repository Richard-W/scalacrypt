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

class RichBigIntSpec extends FlatSpec with Matchers {

  "RichBigInt" should "be convertible to a Seq[Byte]." in {
    val tests = Seq[(Int, Seq[Int])](
      (
        0,
        Seq()
      ), (
        1,
        Seq(1)
      ), (
        255,
        Seq(255)
      ), (
        256,
        Seq(1, 0)
      ), (
        257,
        Seq(1, 1)
      ), (
        511,
        Seq(1, 255)
      )
    )

    for(test <- tests) {
      val int = BigInt(test._1)
      val bytes = test._2 map { _.toByte }

      int.toBytes should be (bytes)
      bytes.toBigInt should be (int)
    }
  }
}
