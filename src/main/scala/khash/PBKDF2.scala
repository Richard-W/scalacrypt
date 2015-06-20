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
package xyz.wiedenhoeft.scalacrypt.khash

import scala.util.{ Try, Success, Failure }
import xyz.wiedenhoeft.scalacrypt._
import scala.annotation.tailrec
import iteratees._

/* Factory for PBKDF2 KeyedHash instances. */
object PBKDF2 {

  /* Creates a Keyed hash that implements PBKDF2. The salt is passed in as the data. */
  def apply(algorithm: KeyedHash[Key], iterations: Int, len: Int): KeyedHash[Key] = new KeyedHash[Key] {

    def length = len

    def apply(key: Key): Try[Iteratee[Seq[Byte], Seq[Byte]]] = {
      algorithm(key) map { initialIteratee ⇒
        Iteratee.fold(initialIteratee) { (iteratee: Iteratee[Seq[Byte], Seq[Byte]], chunk: Seq[Byte]) ⇒
          Success(iteratee.fold(Element(chunk)))
        } flatMap { keyedHash ⇒
          val numBlocks = (length.toFloat / algorithm.length).ceil.toInt

          /* Calculates a block */
          def calcBlock(blockNum: Int): Try[Seq[Byte]] = {
            val blockNumBytes = java.nio.ByteBuffer.allocate(4).putInt(blockNum).array
            val initial: Seq[Byte] = keyedHash.fold(Element(blockNumBytes)).run.get

            @tailrec
            def calcBlockHelper(block: Seq[Byte], previousU: Seq[Byte], iteration: Int): Try[Seq[Byte]] = {
              if (iteration > iterations) {
                Success(block)
              } else {
                val uTry = algorithm(key, previousU)
                if (uTry.isSuccess) {
                  val u = uTry.get
                  calcBlockHelper(block xor u, u, iteration + 1)
                } else {
                  Failure(uTry.failed.get)
                }
              }
            }

            calcBlockHelper(initial, initial, 2)
          }

          val blocks = for (blockNum <- 1 to numBlocks) yield calcBlock(blockNum)
          val failures = blocks filter { _.isFailure }
          if (failures.length == 0) Iteratee.done((blocks map { _.get }).flatten.slice(0, length))
          else Iteratee.error(failures(0).failed.get)
        }
      }
    }

    def verify(key: Key, hash: Seq[Byte]): Try[Iteratee[Seq[Byte], Boolean]] = apply(key) map { _ map { _ == hash } }
  }
}
