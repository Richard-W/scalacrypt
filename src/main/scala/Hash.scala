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
import scala.concurrent.{ Future, Promise }

trait Hash {
  
  /** Returns an iteratee that digests its input to a hash. */
  def apply(): Iteratee[Seq[Byte], Seq[Byte]]

  /** Digests a given sequence of bytes. */
  def apply(data: Seq[Byte]): Seq[Byte] = apply.fold(Element(data)).run.get

  /** Returns a promise of the hash value and an identical iterator. */
  def apply(data: Iterator[Seq[Byte]]): (Iterator[Seq[Byte]], Future[Seq[Byte]]) = {
    val promise = Promise[Seq[Byte]]
    val iterator = new Iterator[Seq[Byte]] {

      var iteratee: Iteratee[Seq[Byte], Seq[Byte]] = apply()

      def hasNext: Boolean = data.hasNext

      def next: Seq[Byte] = {
        val chunk = data.next
        iteratee = iteratee.fold(Element(chunk))
        if(!data.hasNext) {
          val hashTry = iteratee.run
          promise.complete(hashTry)
        }
        chunk
      }
    }
    (iterator, promise.future)
  }

  /** Length of the resulting hash. */
  def length: Int
}
