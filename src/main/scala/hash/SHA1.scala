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
object SHA1 extends Hash {

  def apply: Iteratee[Seq[Byte], Seq[Byte]] = {
    def bytes2word(bytes: Seq[Byte]): Int =
      ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).put(bytes.toArray).getInt(0)

    def word2bytes(word: Int): Seq[Byte] =
      ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(word).array

    def rotLeft(word: Int, r: Int) = {
      (word << r) | (word >>> (32 - r))
    }

    def f(t: Int, b: Int, c: Int, d: Int): Int = {
      if (t < 20) (b & c) | ((~b) & d)
      else if (t < 40) b ^ c ^ d
      else if (t < 60) (b & c) | (b & d) | (c & d)
      else b ^ c ^ d
    }

    def k(t: Int): Int = {
      if (t < 20) 0x5A827999
      else if (t < 40) 0x6ED9EBA1
      else if (t < 60) 0x8F1BBCDC
      else 0xCA62C1D6
    }

    def compressBlock(state: (Int, Int, Int, Int, Int), block: Seq[Byte]): (Int, Int, Int, Int, Int) = {
      val w = ((block.grouped(4).toSeq map { bytes2word(_) }) ++ Seq.fill[Int](64) { 0 }).toArray
      for (i <- (16 until 80)) {
        // This is not functional at all. It runs A LOT faster though.
        w(i) = rotLeft(w(i - 3) ^ w(i - 8) ^ w(i - 14) ^ w(i - 16), 1)
      }

      var a: Int = state._1
      var b: Int = state._2
      var c: Int = state._3
      var d: Int = state._4
      var e: Int = state._5
      var temp: Int = 0

      for (t <- (0 until 80)) {
        temp = rotLeft(a, 5) + f(t, b, c, d) + e + w(t) + k(t)
        e = d
        d = c
        c = rotLeft(b, 30)
        b = a
        a = temp
      }
      (state._1 + a, state._2 + b, state._3 + c, state._4 + d, state._5 + e)
    }

    Iteratee.fold[Seq[Byte], (Int, Int, Int, Int, Int, Long, Seq[Byte])](0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0, 0, Seq()) {
      case ((h0f, h1f, h2f, h3f, h4f, length, buf), input) ⇒
        val newLength = length + input.length
        val buffer = buf ++ input
        val numBlocks = buffer.length / 64
        val newBuf = buffer.slice(numBlocks * 64, buffer.length)
        val blocks = buffer.slice(0, numBlocks * 64).grouped(64).toSeq

        var h0 = h0f
        var h1 = h1f
        var h2 = h2f
        var h3 = h3f
        var h4 = h4f

        for (block <- blocks) {
          val t = compressBlock((h0, h1, h2, h3, h4), block)
          h0 = t._1
          h1 = t._2
          h2 = t._3
          h3 = t._4
          h4 = t._5
        }

        Success((h0, h1, h2, h3, h4, newLength, newBuf))
    } map {
      case (h0f, h1f, h2f, h3f, h4f, length, buf) ⇒
        val messageLength = length
        val bitLength = messageLength * 8
        val bitLengthEncoded = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(bitLength).array.toSeq
        val nullPaddingLength = 64 - ((buf.length + 1 + 8) % 64)
        val lastBlocks = (buf :+ 128.toByte) ++ Seq.fill[Byte](nullPaddingLength) { 0.toByte } ++ bitLengthEncoded

        val blocks = lastBlocks.grouped(64).toSeq

        var h0 = h0f
        var h1 = h1f
        var h2 = h2f
        var h3 = h3f
        var h4 = h4f

        for (block <- blocks) {
          val t = compressBlock((h0, h1, h2, h3, h4), block)
          h0 = t._1
          h1 = t._2
          h2 = t._3
          h3 = t._4
          h4 = t._5
        }

        word2bytes(h0) ++ word2bytes(h1) ++ word2bytes(h2) ++ word2bytes(h3) ++ word2bytes(h4)
    }
  }

  val length = 20

  val blockSize = 64
}
