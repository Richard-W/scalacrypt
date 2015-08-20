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
object SHA256 extends MDConstruction[(Int, Int, Int, Int, Int, Int, Int, Int)] {

  private def bytes2word(bytes: Seq[Byte]): Int =
    ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).put(bytes.toArray).getInt(0)

  private def word2bytes(word: Int): Seq[Byte] =
    ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(word).array

  private def rotRight(word: Int, r: Int) = {
    (word >>> r) | (word << (32 - r))
  }

  private val k = Seq(
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  )

  def compressionFunction(state: (Int, Int, Int, Int, Int, Int, Int, Int), block: Seq[Byte]): (Int, Int, Int, Int, Int, Int, Int, Int) = {
    val w = ((block.grouped(4).toSeq map { bytes2word(_) }) ++ Seq.fill[Int](64) { 0 }).toArray
    for (i <- (16 until 80)) {
      val s0 = rotRight(w(i - 15), 7) ^ rotRight(w(i - 15), 18) ^ (w(i - 15) >>> 3)
      val s1 = rotRight(w(i - 2), 17) ^ rotRight(w(i - 2), 19) ^ (w(i - 2) >>> 10)
      w(i) = w(i - 16) + s0 + w(i - 7) + s1
    }

    @tailrec
    def compressionHelper(state: (Int, Int, Int, Int, Int, Int, Int, Int), t: Int): (Int, Int, Int, Int, Int, Int, Int, Int) = {
      if (t == 64) state
      else state match {
        case (a, b, c, d, e, f, g, h) ⇒
          val s1 = rotRight(e, 6) ^ rotRight(e, 11) ^ rotRight(e, 25)
          val ch = (e & f) ^ ((~e) & g)
          val temp1 = h + s1 + ch + k(t) + w(t)
          val s0 = rotRight(a, 2) ^ rotRight(a, 13) ^ rotRight(a, 22)
          val maj = (a & b) ^ (a & c) ^ (b & c)
          val temp2 = s0 + maj
          compressionHelper((temp1 + temp2, a, b, c, d + temp1, e, f, g), t + 1)
      }
    }

    val (a, b, c, d, e, f, g, h) = compressionHelper((state._1, state._2, state._3, state._4, state._5, state._6, state._7, state._8), 0)
    (state._1 + a, state._2 + b, state._3 + c, state._4 + d, state._5 + e, state._6 + f, state._7 + g, state._8 + h)
  }

  val initialState = (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)

  def addPadding(state: (Int, Int, Int, Int, Int, Int, Int, Int), buf: Seq[Byte], messageLength: Long): Seq[Byte] = {
    val bitLength = messageLength * 8
    val bitLengthEncoded = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(bitLength).array.toSeq
    val nullPaddingLength = 64 - ((buf.length + 1 + 8) % 64)
    (buf :+ 128.toByte) ++ Seq.fill[Byte](nullPaddingLength) { 0.toByte } ++ bitLengthEncoded
  }

  def finalizeState(state: (Int, Int, Int, Int, Int, Int, Int, Int), messageLength: Long): Seq[Byte] = {
    word2bytes(state._1) ++ word2bytes(state._2) ++ word2bytes(state._3) ++ word2bytes(state._4) ++ word2bytes(state._5) ++ word2bytes(state._6) ++ word2bytes(state._7) ++ word2bytes(state._8)
  }

  val length = 32

  val blockSize = 64
}
