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
package xyz.wiedenhoeft.scalacrypt.hash

import xyz.wiedenhoeft.scalacrypt._
import iteratees._
import scala.util.{ Try, Success, Failure }
import scala.annotation.tailrec

/** Template class for hash functions based on the Merkle-Dåmgard construction */
abstract class MDConstruction[StateType] extends Hash {

  def compressionFunction(state: StateType, block: Seq[Byte]): StateType

  def addPadding(state: StateType, buffer: Seq[Byte], messageLength: Long): Seq[Byte]

  def initialState: StateType

  def finalizeState(state: StateType, messageLength: Long): Seq[Byte]

  def apply: Iteratee[Seq[Byte], Seq[Byte]] = {
    @tailrec
    def compressionHelper(state: StateType, blocks: Seq[Seq[Byte]]): StateType = {
      if (blocks.length == 0) {
        state
      } else {
        val newState = compressionFunction(state, blocks.head)
        compressionHelper(newState, blocks.tail)
      }
    }

    Iteratee.fold[Seq[Byte], (StateType, Seq[Byte], Long)]((initialState, Seq(), 0)) {
      case ((state, buffer, length), input) ⇒
        val data = buffer ++ input
        val newLength = length + input.length
        val numBlocks = data.length / this.blockSize
        val blocks = data.slice(0, numBlocks * this.blockSize).grouped(this.blockSize).toSeq
        val newBuffer = data.slice(numBlocks * this.blockSize, data.length)

        val newState = compressionHelper(state, blocks)
        Success(newState, newBuffer, newLength)
    } map {
      case (state, buffer, length) ⇒
        val blocks = addPadding(state, buffer, length).grouped(this.blockSize).toSeq
        val finalState = compressionHelper(state, blocks)
        finalizeState(finalState, length)
    }
  }
}
