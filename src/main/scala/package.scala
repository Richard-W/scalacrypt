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
package xyz.wiedenhoeft.scalacrypt

import java.util.Base64

import scala.util.{ Try, Success, Failure }

object `package` {

  import scala.language.implicitConversions

  /** Implicit Conversion that adds the toKey method to every class. */
  implicit def toCanBuildKeyOp[FromType](from: FromType) = {
    new MightBuildKeyOp[FromType](from)
  }

  implicit def toRichByteSeq(value: Seq[Byte]): RichByteSeq = new RichByteSeq(value)
  /** Adds methods to Seq[Byte]. */
  class RichByteSeq(value: Seq[Byte]) {

    def toBase64String: String = Base64.getEncoder.encodeToString(value.toArray)

    def xor(other: Seq[Byte]): Seq[Byte] = {
      def min(a: Int, b: Int): Int = if (a < b) a else b
      for (i <- (0 until min(value.length, other.length))) yield (value(i) ^ other(i)).toByte
    }

    def os2ip: BigInt = {
      def byteToInt(byte: Byte): Int = {
        val result = byte.toInt
        if (result < 0) result + 256
        else result
      }

      var result = BigInt(0)
      for (i <- (0 until value.length)) {
        val exponent = value.length - 1 - i
        result += (BigInt(256) pow exponent) * byteToInt(value(i))
      }
      result
    }
  }

  implicit def toRichString(value: String): RichString = new RichString(value)
  /** Adds methods to String. */
  class RichString(value: String) {

    def toBase64Bytes: Seq[Byte] = Base64.getDecoder.decode(value.filter(!_.isWhitespace))
  }

  implicit def toRichBigInt(value: BigInt): RichBigInt = new RichBigInt(value)
  /** Adds methods to BigInt. */
  class RichBigInt(value: BigInt) {

    /** I2OSP as defined by PKCS#1 v2.1 */
    def i2osp(length: Int): Try[Seq[Byte]] = {
      val base = BigInt(256)
      var exponent = length

      if (length <= 0) return Failure(new Exception("Invalid length"))
      if (value < 0) return Failure(new Exception("Negative values can not be converted using I2OSP"))
      val maxValue = (base pow exponent) - 1
      if (value > maxValue) return Failure(new Exception(s"Value too large: $value (max. $maxValue when length is $length)"))

      var remaining = value
      val result = new Array[Byte](length)

      /* Calculate the digits (base 256, big endian). */
      while (exponent > 0) {
        exponent -= 1

        val factor = base pow exponent
        val remainingBackup = remaining
        remaining = remaining mod factor
        val difference = remainingBackup - remaining
        val index = (length - 1) - exponent
        result(index) = (difference / factor).toByte
      }

      Success(result)
    }
  }

  type Parameters = Map[Symbol, Any]
}
