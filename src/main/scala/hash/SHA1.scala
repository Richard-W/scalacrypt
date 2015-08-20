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
import java.nio.{ ByteBuffer, ByteOrder }
import scala.annotation.tailrec

/** Secure Hash Algorithm 1 */
object SHA1 extends MDConstruction[(Int, Int, Int, Int, Int)] {

  private def bytes2word(bytes: Seq[Byte]): Int =
    ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).put(bytes.toArray).getInt(0)

  private def word2bytes(word: Int): Seq[Byte] =
    ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(word).array

  private def rotLeft(word: Int, r: Int) = {
    (word << r) | (word >>> (32 - r))
  }

  private def f(t: Int, b: Int, c: Int, d: Int): Int = {
    if (t < 20) (b & c) | ((~b) & d)
    else if (t < 40) b ^ c ^ d
    else if (t < 60) (b & c) | (b & d) | (c & d)
    else b ^ c ^ d
  }

  private def k(t: Int): Int = {
    if (t < 20) 0x5A827999
    else if (t < 40) 0x6ED9EBA1
    else if (t < 60) 0x8F1BBCDC
    else 0xCA62C1D6
  }

  def compressionFunction(state: (Int, Int, Int, Int, Int), block: Seq[Byte]): (Int, Int, Int, Int, Int) = {
    val w = ((block.grouped(4).toSeq map { bytes2word(_) }) ++ Seq.fill[Int](64) { 0 }).toArray
    for (i <- (16 until 80)) {
      // This is not functional at all. It runs A LOT faster though.
      w(i) = rotLeft(w(i - 3) ^ w(i - 8) ^ w(i - 14) ^ w(i - 16), 1)
    }

    @tailrec
    def compressionHelper(state: (Int, Int, Int, Int, Int), t: Int): (Int, Int, Int, Int, Int) = {
      if (t == 80) state
      else state match {
        case (a, b, c, d, e) ⇒
          compressionHelper((rotLeft(a, 5) + f(t, b, c, d) + e + w(t) + k(t), a, rotLeft(b, 30), c, d), t + 1)
      }
    }

    val (a, b, c, d, e) = compressionHelper((state._1, state._2, state._3, state._4, state._5), 0)
    (state._1 + a, state._2 + b, state._3 + c, state._4 + d, state._5 + e)
  }

  val initialState = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)

  def addPadding(state: (Int, Int, Int, Int, Int), buffer: Seq[Byte], messageLength: Long): Seq[Byte] = {
    val bitLength = messageLength * 8
    val bitLengthEncoded = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(bitLength).array.toSeq
    val nullPaddingLength = 64 - ((buffer.length + 1 + 8) % 64)
    (buffer :+ 128.toByte) ++ Seq.fill[Byte](nullPaddingLength) { 0.toByte } ++ bitLengthEncoded
  }

  def finalizeState(state: (Int, Int, Int, Int, Int), messageLength: Long): Seq[Byte] = {
    word2bytes(state._1) ++ word2bytes(state._2) ++ word2bytes(state._3) ++ word2bytes(state._4) ++ word2bytes(state._5)
  }

  val length = 20

  val blockSize = 64
}
