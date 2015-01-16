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

trait Enumeratee[From, To] {

  def apply[A](inner: Iteratee[To, A]): Iteratee[From, Iteratee[To, A]]

  def transform[A](inner: Iteratee[To, A]): Iteratee[From, A] = apply(inner) flatMap {
    _.fold(EOF).state match {
      case Cont(_) ⇒
      new Iteratee[From, A] { val state = Error[From, A](new IterateeException("Iteratee must be done after EOF")) }

      case Error(error) ⇒
      new Iteratee[From, A] { val state = Error[From, A](error) }

      case Done(result) ⇒
      new Iteratee[From, A] { val state = Done[From, A](result) }
    }
  }
}

object Enumeratee {

  def map[From, To](f: (From) ⇒ To) = new Enumeratee[From, To] {
    def apply[A](inner: Iteratee[To, A]): Iteratee[From, Iteratee[To, A]] = new Iteratee[From, Iteratee[To, A]] {
      val state: State[From, Iteratee[To, A]] = inner.state match {
        case Cont(folder) ⇒
        Cont((input: Input[From]) ⇒ input match {
          case Element(el) ⇒ apply(inner.fold(Element(f(el))))
          case Empty ⇒ apply(inner)
          case EOF ⇒ new Iteratee[From, Iteratee[To, A]] { val state = Done[From, Iteratee[To, A]](inner) }
        })

        case _ ⇒
        Done(inner)
      }
    }
  }
}
