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
package xyz.wiedenhoeft.scalacrypt.iteratees

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

/** An immutable structure that transforms a set of data to a result.
  *
  * An iteratee is an immutable structure that can consume an input to
  * create a iteratee. An iteratee is only defined by its state which can
  * be either Cont, Error or Done. Cont holds a closure that defines the next
  * Iteratee depending on the next input. Done holds the result and Error holds
  * a Throwable.
  *
  * There are three different types of Input: Element, Empty and EOF.
  * The meaning of Element and Empty depends on the implementation, but
  * as soon as an EOF is encountered the resulting new Iteratee must be
  * in the Done state.
  */
trait Iteratee[E, A] {

  val state: State[E, A]

  /** Consume an Input to Create a new Iteratee */
  def fold(input: Input[E]): Iteratee[E, A] = state match {
    case Cont(folder) ⇒
    folder(input)

    case _ ⇒
    this
  }

  /** Push an EOF and try to get the result. */
  def run: Try[A] = fold(EOF).state match {
    case Cont(_) ⇒
    Failure(new IterateeException("State should be a Done after EOF."))

    case Done(result) ⇒
    Success(result)

    case Error(error) ⇒
    Failure(error)
  }

  /** As soon as this iteratee finishes inputs are given to the new iteratee
    * defined by f eventually producing a B.
    */
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

  /** Map the result using f. */
  def map[B](f: (A) ⇒ B): Iteratee[E, B] = flatMap { result ⇒
    new Iteratee[E, B] {
      val state = Done[E, B](f(result))
    }
  }
}

object Iteratee {

  /** Create a new iteratee that uses its result type as a state that is passed to its folder.
    *
    * The resulting iteratee ignores empty inputs and results in A only after an EOF. In
    * combination with the map-method this iteratee is sufficient for most purposes.
    */
  def fold[E, A](initial: A)(folder: (A, E) ⇒ A) = {
    def getIteratee(intermediate: A): Iteratee[E, A] = new Iteratee[E, A] {
      val currentResult = intermediate

      val state = Cont((input: Input[E]) ⇒ input match {
        case Element(element) ⇒ getIteratee(folder(currentResult, element))
        case Empty ⇒ this
        case EOF ⇒ new Iteratee[E, A] { val state = Done[E, A](currentResult) }
      })
    }

    getIteratee(initial)
  }

  /** Returns an iteratee that is already in the Done state with the given result. */
  def done[E, A](result: A) = new Iteratee[E, A] { val state = Done[E, A](result) }
}
