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

trait Enumerator[E] {

  /** Apply enumerator to iteratee producing a new iteratee. */
  def apply[A](iteratee: Iteratee[E, A]): Iteratee[E, A]

  /** Every element creates a new Enumerator via f. On apply
    * all these enumerators are applied to the iteratee.
    */
  def flatMap[B](f: (E) ⇒ Enumerator[B]): Enumerator[B] = {
    val base = this

    new Enumerator[B] {
      def apply[A](iteratee: Iteratee[B, A]): Iteratee[B, A] = {
        base(Iteratee.fold[E, Iteratee[B, A]](iteratee) { (i, e) ⇒
          f(e).apply(i)
        }).run.get
      }
    }
  }

  /** Converts all Inputs of the Enumerator using f */
  def map[B](f: (E) ⇒ B) = flatMap { e ⇒
    new Enumerator[B] { def apply[A](iteratee: Iteratee[B, A]) = { iteratee.fold(Element(f(e))) } }
  }

  /** Applies the enumerator and pushes EOF. */
  def run[A](iteratee: Iteratee[E, A]): Try[A] = {
    apply(iteratee).run
  }
}

object Enumerator {

  /** Creates an enumerator that applies all given arguments to an iteratee. */
  def apply[E](elements: E*): Enumerator[E] = new Enumerator[E] {

    def apply[A](iteratee: Iteratee[E, A]): Iteratee[E, A] = {
      def applySeqToIteratee(s: Seq[E], i: Iteratee[E, A]): Iteratee[E, A] = {
        if(s.isEmpty) i
        else applySeqToIteratee(s.tail, i.fold(Element(s.head)))
      }

      applySeqToIteratee(elements, iteratee)
    }
  }
}
