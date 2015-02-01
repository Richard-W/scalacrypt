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
package xyz.wiedenhoeft.scalacrypt.iteratees

import scala.util.{ Try, Success, Failure }
import xyz.wiedenhoeft.scalacrypt._

trait Enumeratee[From, To] {

  def apply[A](inner: Iteratee[To, A]): Iteratee[From, Iteratee[To, A]]

  def transform[A](inner: Iteratee[To, A]): Iteratee[From, A] = apply(inner) flatMap {
    _.fold(EOF).state match {
      case Cont(_) ⇒ Iteratee.error(new IterateeException("Iteratee must be done after EOF"))
      case Error(error) ⇒ Iteratee.error(error)
      case Done(result) ⇒ Iteratee.done(result)
    }
  }
}

object Enumeratee {

  def map[From, To](f: (From) ⇒ To) = new Enumeratee[From, To] {
    def apply[A](inner: Iteratee[To, A]): Iteratee[From, Iteratee[To, A]] = inner.state match {
      case Cont(folder) ⇒ Iteratee.cont {
        case Element(element) ⇒ apply(inner.fold(Element(f(element))))
        case Empty ⇒ apply(inner)
        case EOF ⇒ Iteratee.done(inner)
      }
      case _ ⇒ Iteratee.done(inner)
    }
  }
}
