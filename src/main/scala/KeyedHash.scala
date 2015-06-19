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

import scala.util.{ Try, Success, Failure }
import iteratees._
import scala.concurrent.{ Promise, Future }

/** Base class for Keyed hash (Message Authentication Code) implementations. */
trait KeyedHash[KeyType <: Key] {

  /** Returns an iteratee calculating the MAC. */
  def apply(key: KeyType): Try[Iteratee[Seq[Byte],Seq[Byte]]]

  /** Calculates the MAC. */
  def apply(key: KeyType, data: Seq[Byte]): Try[Seq[Byte]] = apply(key) flatMap {
    _.fold(Element(data)).run
  }

  /** Takes an iterator of data and returns a future containing the hash and an identical iterator */
  def apply(key: KeyType, data: Iterator[Seq[Byte]]): Try[(Iterator[Seq[Byte]], Future[Seq[Byte]])] = {
    val promise = Promise[Seq[Byte]]
    val iteratorTry = apply(key) map { initIteratee ⇒
      new Iterator[Seq[Byte]] {

        var iteratee = initIteratee

        def hasNext = data.hasNext

        def next = {
          val chunk = data.next
          iteratee = iteratee.fold(Element(chunk))
          if(!data.hasNext) {
            promise.complete(iteratee.run)
          }
          chunk
        }
      }
    }
    iteratorTry map { iterator ⇒
      (iterator, promise.future)
    }
  }

  def verify(key: KeyType, hash: Seq[Byte]): Try[Iteratee[Seq[Byte], Boolean]]

  def verify(key: KeyType, data: Seq[Byte], hash: Seq[Byte]): Try[Boolean] = verify(key, hash) flatMap {
    _.fold(Element(data)).run
  }

  /** The length in bytes of the MAC. */
  def length: Int
}
