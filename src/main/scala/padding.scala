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

trait PKCS7Padding extends BlockPadding {

  def pad(input: Iterator[Seq[Byte]], blockSize: Int): Iterator[Seq[Byte]] = {
    new Iterator[Seq[Byte]] {
      
      var running = true
      var buffer: Seq[Byte] = Seq[Byte]()

      def hasNext: Boolean = running

      def next: Seq[Byte] = {
        while(buffer.length < blockSize && input.hasNext) {
          buffer = buffer ++ input.next
        }

        if(buffer.length >= blockSize) {
          val rv = buffer.slice(0, blockSize)
          buffer = buffer.slice(blockSize, buffer.length)
          rv
        } else {
          val missing = blockSize - buffer.length
          running = false
          buffer ++ (for(_ <- 0 until missing) yield missing.toByte)
        }
      }
    }
  }

  def unpad(input: Iterator[Seq[Byte]], blockSize: Int): Iterator[Try[Seq[Byte]]] = {
    var error: Option[Throwable] = None

    val rv: Iterator[Try[Seq[Byte]]] = new Iterator[Try[Seq[Byte]]] {

      var buffer: Seq[Byte] = if(input.hasNext) {
        input.next
      } else {
        error = Some(new BadPaddingException("Input is empty."))
        Seq()
      }
      if(buffer.length != blockSize) {
        error = Some(new IllegalBlockSizeException("BlockPadding.unwrap only accepts an iterator of correct blocks."))
        Seq()
      }

      def hasNext = buffer.length != 0

      def next: Try[Seq[Byte]] = {
        //Peek the next block.
        val nextBlock: Seq[Byte] = if(input.hasNext) {
          val next = input.next
          //Check the block size.
          if(next.length != blockSize) {
            return Failure(new IllegalBlockSizeException("BlockPadding.unwrap only accepts an iterator of correct blocks."))
          }
          next
        } else {
          Seq()
        }

        if(input.hasNext) {
          //After peeking there is still input left so neither
          //buffer nor nextBlock contain the padding.
          val rv = buffer
          buffer = nextBlock
          Success(rv)
        } else {
          //No input left. Concatenate blocks and remove the padding.
          val block = buffer ++ nextBlock
          buffer = Seq()

          //Get the padding length
          val lastByte = block.last
          val paddingLength = if(lastByte.toInt < 0) {
            lastByte.toInt + 256
          } else {
            lastByte.toInt
          }

          //Check the padding and return
          val padding: Seq[Byte] = for(_ <- 0 until paddingLength) yield lastByte
          if(block.slice(block.length - paddingLength, block.length) == padding)
            Success(block.slice(0, block.length - paddingLength))
          else
            Failure(new BadPaddingException("Invalid padding"))
        }
      }
    }

    error match {
      case Some(f) ⇒
      Iterator(Failure(f))

      case _ ⇒
      rv
    }
  }
}
