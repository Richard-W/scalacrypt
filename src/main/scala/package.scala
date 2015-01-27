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

object `package` {

  import scala.language.implicitConversions

  /** Implicit Conversion that adds the toKey method to every class. */
  implicit def toCanBuildKeyOp[FromType](from: FromType) = {
    new MightBuildKeyOp[FromType](from)
  }

  implicit def toRichByteSeq(value: Seq[Byte]): RichByteSeq = new RichByteSeq(value)
  /** Adds methods to Seq[Byte]. */
  class RichByteSeq(value: Seq[Byte]) {

    def toBase64String: String = (new sun.misc.BASE64Encoder).encodeBuffer(value.toArray)

    def xor(other: Seq[Byte]): Seq[Byte] = {
      def min(a: Int, b: Int): Int = if(a < b) a else b
      for(i <- (0 until min(value.length, other.length))) yield (value(i) ^ other(i)).toByte
    }

    def toBigInt: BigInt = {
      def byteToInt(byte: Byte): Int = {
        val result = byte.toInt
        if(result < 0) result + 256
        else result
      }

      var result = BigInt(0)
      for(i <- (0 until value.length)) {
        val exponent = value.length - 1 - i
        result += (BigInt(256) pow exponent) * byteToInt(value(i))
      }
      result
    }
  }

  implicit def toRichString(value: String): RichString = new RichString(value)
  /** Adds methods to String. */
  class RichString(value: String) {

    def toBase64Bytes: Seq[Byte] = (new sun.misc.BASE64Decoder).decodeBuffer(value)
  }

  implicit def toRichBigInt(value: BigInt): RichBigInt = new RichBigInt(value)
  /** Adds methods to BigInt. */
  class RichBigInt(value: BigInt) {

    def toBytes: Seq[Byte] = {
      var remaining = value
      var result = Seq[Byte]()
      val base = BigInt(256)

      /* Calculate the position of the most significant digit (base 256). */
      var exponent = 0
      var exponentNumber = BigInt(1)
      while(value > exponentNumber) {
        exponent += 1
        exponentNumber = base pow exponent
      }

      /* Calculate the digits (base 256, big endian). */
      while(exponent > 0) {
        exponent -= 1

        val factor = base pow exponent
        val remainingBackup = remaining
        remaining = remaining mod factor
        val difference = remainingBackup - remaining
        result = result :+ (difference / factor).toByte
      }

      result
    }
  }
}
