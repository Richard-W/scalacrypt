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
package xyz.wiedenhoeft.scalacrypt.paddings

import xyz.wiedenhoeft.scalacrypt._
import scala.util.{ Try, Success, Failure }

trait OAEP extends BlockPadding {

  /** Generates the hash that is xored with m. */
  def hash1: Hash

  /** Generates the hash that is xored with r. */
  def hash2: Hash

  /** Length of the random part. */
  lazy val k0: Int = hash2.length

  /** Number of zeroes appended to m. */
  def k1: Int

  def pad(data: Iterator[Seq[Byte]]): Iterator[Seq[Byte]] = new Iterator[Seq[Byte]] {

    def hasNext = data.hasNext

    def next: Seq[Byte] = {
      val m = data.next ++ Seq.fill[Byte](k1) { 0.toByte }
      val r = Random.nextBytes(k0)
      val x = m xor hash1(r)
      val y = r xor hash2(x)
      x ++ y
    }
  }

  def unpad(data: Iterator[Seq[Byte]]): Iterator[Try[Seq[Byte]]] = new Iterator[Try[Seq[Byte]]] {

    def hasNext = data.hasNext
    
    def next: Try[Seq[Byte]] = {
      val next = data.next
      val xylen = hash1.length + hash2.length
      if(next.length > xylen) return Failure(new BadPaddingException("Invalid length: " + next.length))
      val xy = next ++ Seq.fill[Byte](xylen - next.length) { 0.toByte }

      val x = xy.slice(0, hash2.length)
      val y = xy.slice(hash2.length, xy.length)
      val r = y xor hash2(x)
      val m = x xor hash2(r)

      val zeroes = m.slice(m.length - k1, m.length)
      if(zeroes != Seq.fill[Byte](k1) { 0.toByte }) return Failure(new BadPaddingException("No nullbytes"))

      Success(m.slice(0, m.length - k1))
    }
  }
}
