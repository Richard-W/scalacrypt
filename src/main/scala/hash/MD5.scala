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
object MD5 extends MDConstruction[(Int, Int, Int, Int)] {

  private def bytes2word(bytes: Seq[Byte]): Int =
    ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).put(bytes.toArray).getInt(0)

  private def word2bytes(word: Int): Seq[Byte] =
    ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(word).array

  private def rotLeft(word: Int, r: Int) = {
    (word << r) | (word >>> (32 - r))
  }

  private def f(t: Int, b: Int, c: Int, d: Int): Int = {
    if (t < 16) (b & c) | ((~b) & d)
    else if (t < 32) (b & d) | (c & (~d))
    else if (t < 48) b ^ c ^ d
    else c ^ (b | (~d))
  }

  private val s = Seq(
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
  )

  private val k = Seq(
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
  )

  private def g(t: Int): Int = {
    if (t < 16) t
    else if (t < 32) (5 * t + 1) % 16
    else if (t < 48) (3 * t + 5) % 16
    else (7 * t) % 16
  }

  def compressionFunction(state: (Int, Int, Int, Int), block: Seq[Byte]): (Int, Int, Int, Int) = {
    val w = block.grouped(4).toSeq map { bytes2word(_) }

    @tailrec
    def compressionHelper(state: (Int, Int, Int, Int), t: Int): (Int, Int, Int, Int) = {
      if (t == 64) state
      else state match { case (a, b, c, d) ⇒ compressionHelper((d, b + rotLeft(a + f(t, b, c, d) + k(t) + w(g(t)), s(t)), b, c), t + 1) }
    }

    val (a, b, c, d) = compressionHelper((state._1, state._2, state._3, state._4), 0)
    (state._1 + a, state._2 + b, state._3 + c, state._4 + d)
  }

  val initialState = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)

  def addPadding(state: (Int, Int, Int, Int), buffer: Seq[Byte], messageLength: Long): Seq[Byte] = {
    val bitLength = messageLength * 8
    val bitLengthEncoded = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(bitLength).array.toSeq
    val nullPaddingLength = 64 - ((buffer.length + 1 + 8) % 64)
    (buffer :+ 128.toByte) ++ Seq.fill[Byte](nullPaddingLength) { 0.toByte } ++ bitLengthEncoded
  }

  def finalizeState(state: (Int, Int, Int, Int), messageLength: Long): Seq[Byte] = {
    word2bytes(state._1) ++ word2bytes(state._2) ++ word2bytes(state._3) ++ word2bytes(state._4)
  }

  val length = 16

  val blockSize = 64
}

