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

/** Base class for Keyed hash (Message Authentication Code) implementations. */
trait KeyedHash[KeyType <: Key] {

  /** Returns an iteratee calculating the MAC. */
  def apply(key: KeyType): Try[Iteratee[Seq[Byte],Seq[Byte]]]

  /** Calculates the MAC. */
  def apply(data: Seq[Byte], key: KeyType): Try[Seq[Byte]] = apply(key) flatMap {
    _.fold(Element(data)).run
  }

  /** Takes an iterator of data and returns an iterator containing a
    * tuple of both the data chunk and an option finally containing the hash. */
  def apply(data: Iterator[Seq[Byte]], key: KeyType): Try[Iterator[(Seq[Byte], Option[Try[Seq[Byte]]])]] = {
    apply(key) map { initialIteratee ⇒
      new Iterator[(Seq[Byte], Option[Try[Seq[Byte]]])] {
        var lastIteratee = initialIteratee

        def hasNext = data.hasNext
        def next = {
          val chunk = data.next
          lastIteratee = lastIteratee.fold(Element(chunk))
          (chunk, if(!hasNext) Some(lastIteratee.fold(EOF).run) else None)
        }
      }
    }
  }

  def verify(hash: Seq[Byte], key: KeyType): Try[Iteratee[Seq[Byte], Boolean]]

  def verify(data: Seq[Byte], hash: Seq[Byte], key: KeyType): Try[Boolean] = verify(hash, key) flatMap {
    _.fold(Element(data)).run
  }

  /** The length in bytes of the MAC. */
  def length: Int
}
