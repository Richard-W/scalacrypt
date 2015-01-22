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
package xyz.wiedenhoeft.scalacrypt.khash

import scala.util.{ Try, Success, Failure }
import xyz.wiedenhoeft.scalacrypt._
import iteratees._

/* Factory for PBKDF2 KeyedHash instances. */
object PBKDF2 {
  
  /* Creates a Keyed hash that implements PBKDF2. The salt is passed in as the data. */
  def apply(algorithm: KeyedHash, iterations: Int, len: Int): KeyedHash = new KeyedHash {

    def length = len

    def apply(key: Key): Iteratee[Seq[Byte], Seq[Byte]] = Iteratee.fold(algorithm(key)) { (iteratee: Iteratee[Seq[Byte], Seq[Byte]], chunk: Seq[Byte]) ⇒
      iteratee.fold(Element(chunk))
    } map { keyedHash ⇒
      val numBlocks = (length.toFloat / algorithm.length).ceil.toInt

      def xor(a: Seq[Byte], b: Seq[Byte]): Seq[Byte] = {
        for(i <- 0 until a.length) yield (a(i) ^ b(i)).toByte
      }

      /* Returns the tuple (block, Uc). */
      def u(iteration: Int, u1: Seq[Byte]): (Seq[Byte], Seq[Byte]) = {
        if(iteration == 1) (u1, u1)
        else {
          val (block, prevU) = u(iteration - 1, u1)
          val currentU = algorithm(prevU, key)
          (xor(block, currentU), currentU)
        }
      }

      /* Calculates a block */
      def f(blockNum: Int): Seq[Byte] = {
        val u1: Seq[Byte] = keyedHash.fold(Element(java.nio.ByteBuffer.allocate(4).putInt(blockNum).array)).run.get
        u(iterations, u1)._1
      }

      (for(blockNum <- 1 to numBlocks) yield f(blockNum)).flatten.slice(0, len)
    }
  }
}
