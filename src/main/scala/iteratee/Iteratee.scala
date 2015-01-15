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
package xyz.wiedenhoeft.scalacrypt.iteratee

import scala.util.{ Try, Success, Failure }
import xyz.wiedenhoeft.scalacrypt._

sealed trait State[E, A]

case class Cont[E, A](folder: (Input[E]) ⇒ Iteratee[E, A]) extends State[E, A]
case class Done[E, A](result: A) extends State[E, A]
case class Error[E, A](error: Throwable) extends State[E, A]

sealed trait Input[+E]

case class Element[E](e: E) extends Input[E]
object Empty extends Input[Nothing]
object EOF extends Input[Nothing]

trait Iteratee[E, A] {

  /** After folding an EOF the state MUST be Done. */
  val state: State[E, A]

  def fold(input: Input[E]) = state match {
    case Cont(folder) ⇒
    folder(input)

    case _ ⇒
    this
  }

  def run: Try[A] = fold(EOF).state match {
    case Cont(_) ⇒
    Failure(new IterateeException("State should be a Done after EOF."))

    case Done(result) ⇒
    Success(result)

    case Error(error) ⇒
    Failure(error)
  }

  def flatMap[B](f: (A) ⇒ Iteratee[E, B]): Iteratee[E, B] = state match {
    case Cont(folder) ⇒
    new Iteratee[E, B] {
      val state = Cont[E, B]((input: Input[E]) ⇒ folder(input).flatMap(f))
    }

    case Done(result) ⇒
    f(result)

    case Error(error) ⇒
    new Iteratee[E, B] {
      val state = Error[E, B](error)
    }
  }

  def map[B](f: (A) ⇒ B): Iteratee[E, B] = flatMap { result ⇒
    new Iteratee[E, B] {
      val state = Done[E, B](f(result))
    }
  }
}

object Iteratee {
  def fold[E, A](initial: A)(folder: (E, A) ⇒ A) = {
    def getIteratee(intermediate: A): Iteratee[E, A] = new Iteratee[E, A] {
      val currentResult = intermediate

      val state = Cont((input: Input[E]) ⇒ input match {
        case Element(element) ⇒ getIteratee(folder(element, currentResult))
        case Empty ⇒ this
        case EOF ⇒ new Iteratee[E, A] { val state = Done[E, A](currentResult) }
      })
    }

    getIteratee(initial)
  }
}
