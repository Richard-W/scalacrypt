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
package xyz.wiedenhoeft.scalacrypt.padding

import xyz.wiedenhoeft.scalacrypt._
import scala.util.{ Try, Success, Failure }

trait NoPadding extends BlockPadding {

  def pad(input: Iterator[Seq[Byte]]): Iterator[Seq[Byte]] = new Iterator[Seq[Byte]] {

    var buffer = Seq[Byte]()

    def hasNext = input.hasNext || buffer.length > 0

    def next = {
      while(buffer.length < blockSize && input.hasNext) {
        buffer = buffer ++ input.next
      }
      if(buffer.length < blockSize) {
        //Most likely yields an error in the block cipher
        buffer
      } else {
        val rv = buffer.slice(0, blockSize)
        buffer = buffer.slice(blockSize, buffer.length)
        rv
      }
    }
  }

  def unpad(input: Iterator[Seq[Byte]]): Iterator[Try[Seq[Byte]]] = input map { Success(_) }
}
