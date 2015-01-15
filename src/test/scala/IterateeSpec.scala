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

import iteratee._
import org.scalatest._
import scala.util.{ Try, Success, Failure }

class IterateeSpec extends FlatSpec with Matchers {
  val concatProto = Iteratee.fold[String, String]("") { (e, a) ⇒
    a ++ e
  }

  "An Iteratee" should "be able to concat strings." in {
    var concat = concatProto
    concat = concat.fold(Element("Hello "))
    concat = concat.fold(Empty)
    concat = concat.fold(Element("world"))
    val res = concat.run

    res shouldBe a [Success[_]]
    res.get should be ("Hello world")
  }

  it should "have a working map method" in {
    var counter = concatProto map { str ⇒
      str.length
    }

    counter = counter.fold(Element("Hello "))
    counter = counter.fold(Empty)
    counter = counter.fold(Element("world"))
    val res = counter.run

    res shouldBe a [Success[_]]
    res.get should be (11)
  }
}
