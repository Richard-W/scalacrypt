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

import iteratees._
import org.scalatest._
import scala.util.{ Try, Success, Failure }

class IterateeSpec extends FlatSpec with Matchers {
  val concatProto = Iteratee.fold[String, String]("") { (a, e) ⇒
    Success(a ++ e)
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

  val enumHello = Enumerator("Hello ", "world")

  "An Enumerator" should "be applicable to an iteratee." in {
    enumHello.run(concatProto).get should be ("Hello world")
  }

  it should "have a working flatMap method." in {
    val separators = enumHello.flatMap { e ⇒
      new Enumerator[String] {
        def apply[A](iteratee: Iteratee[String, A]) = {
          iteratee.fold(Element(e)).fold(Element("/"))
        }
      }
    }

    separators.run(concatProto).get should be ("Hello /world/")
  }

  it should "have a working map method." in {
    val counts = enumHello map { _.length.toString + " " }
    counts.run(concatProto).get should be ("6 5 ")
  }

  val sum = Iteratee.fold(0) { (a: Int, e: Int) ⇒ Success(a + e) }
  val toInt = Enumeratee.map { (str: String) ⇒ str.toInt }

  val intEnum1 = Enumerator(5, 5, 1) // Sum 11
  val stringEnum = Enumerator("2", "4", "6") // Sum 12 / 23
  val intEnum2 = Enumerator(3, 4) // Sum 7 / 30

  "An Enumeratee" should "be able to map input to an Iteratee" in {
    val sum1 = intEnum1(sum)
    val sum2 = toInt(sum1)
    val sum3 = stringEnum(sum2)
    val sum4 = sum3.run.get
    val sum5 = intEnum2(sum4)
    sum5.run.get should be (30)
  }

  it should "be able to transform an Iteratee" in {
    val sum1 = intEnum1(sum)
    val sum2 = toInt.transform(sum1)
    val sum3 = stringEnum(sum2)
    sum3.run.get should be (23)
  }

  "Iteratee.done" should "return an Iteratee which is Done." in {
    val iteratee = Iteratee.done[Any, Boolean](true)
    iteratee.state shouldBe a [Done[_,_]]
    iteratee.run.get should be (true)
  }
}
