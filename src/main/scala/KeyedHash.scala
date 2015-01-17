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

import scala.util.{ Try, Success, Failure }
import iteratees._

/** Base class for Keyed hash (Message Authentication Code) implementations. */
trait KeyedHash {

  /** Calculates the MAC. */
  def apply(data: Seq[Byte], key: SymmetricKey): Seq[Byte] = {
    apply(key).fold(Element(data)).run.get
  }

  /** Returns an iteratee calculating the MAC. */
  def apply(key: SymmetricKey): Iteratee[Seq[Byte],Seq[Byte]]

  /** Takes an iterator of data and returns an iterator containing a
    * tuple of both the data chunk and an updated mac iteratee. */
  def apply(data: Iterator[Seq[Byte]], key: SymmetricKey): Iterator[(Seq[Byte], Iteratee[Seq[Byte], Seq[Byte]])] = {
    new Iterator[(Seq[Byte], Iteratee[Seq[Byte], Seq[Byte]])] {
      var lastIteratee = apply(key)

      def hasNext = data.hasNext
      def next = {
        val chunk = data.next
        lastIteratee = lastIteratee.fold(Element(chunk))
        if(!hasNext) lastIteratee = lastIteratee.fold(EOF)
        (chunk, lastIteratee)
      }
    }
  }

  /** The length in bytes of the MAC. */
  def length: Int
}
