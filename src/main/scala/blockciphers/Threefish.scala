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
package xyz.wiedenhoeft.scalacrypt.blockciphers

import xyz.wiedenhoeft.scalacrypt._
import scala.util.{ Try, Success, Failure }
import scala.annotation.tailrec
import java.nio.{ ByteBuffer, ByteOrder }

object Threefish {

  def bytes2word(bytes: Seq[Byte]): Long =
    ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).put(bytes.toArray).getLong(0)

  def word2bytes(word: Long): Seq[Byte] =
    ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(word).array

  def block2words(block: Seq[Byte]): Seq[Long] =
    for(byteWord <- block.grouped(8).toSeq) yield bytes2word(byteWord)

  def words2block(words: Seq[Long]): Seq[Byte] =
    (for(word <- words) yield word2bytes(word)).flatten

  def mix(a: Long, b: Long, r: Int): Seq[Long] = {
    val x = a + b
    val y = ((b << r) | (b >>> (64 - r))) ^ x
    Seq(x, y)
  }

  def unmix(x: Long, y: Long, r: Int): Seq[Long] = {
    val z = y ^ x
    val b = ((z >>> r) | (z << (64 - r)))
    val a = x - b
    Seq(a, b)
  }
}

/** Threefish block cipher. */
trait Threefish[KeyType <: Key] extends BlockCipher[KeyType] {

  import Threefish._

  /** The tweak of this block cipher. */
  def tweak: Seq[Byte]

  /** Rotational constants for the cipher. */
  def rotations: Seq[Seq[Int]]

  /** Permutation used by the cipher. */
  def permutation: Seq[Int]

  /** Reverse permutation used by the cipher. */
  def reversePermutation: Seq[Int]

  /** Number of rounds applied. */
  def numRounds: Int

  /** The number of words this cipher processes in one block. */
  lazy val numWords = blockSize / 8

  lazy val tweakWords: Seq[Long] = {
    val words = block2words(tweak)
    words :+ (words(0) ^ words(1))
  }

  lazy val keyWords: Seq[Long] = {
    @tailrec
    def xorSeq(result: Long, list: List[Long]): Long =
      if(list != Nil)
        xorSeq(result ^ list.head, list.tail)
      else
        result

    val words = block2words(key.bytes)
    words :+ xorSeq(0x1BD11BDAA9FC1A22L, words.toList)
  }

  lazy val roundKeys: Seq[Seq[Long]] = {
    def genRoundKey(s: Int) = {
      for(i <- (0 until numWords)) yield {
        if(i == numWords - 1)
          keyWords((s + i) % (numWords + 1)) + s
        else if(i == numWords - 2)
          keyWords((s + i) % (numWords + 1)) + tweakWords((s + 1) % 3)
        else if(i == numWords - 3)
          keyWords((s + i) % (numWords + 1)) + tweakWords(s % 3)
        else
          keyWords((s + i) % (numWords + 1))
      }
    }

    for(s <- (0 to (numRounds / 4))) yield genRoundKey(s)
  }

  def encryptBlock(block: Seq[Byte]): Try[Seq[Byte]] = {
    if(block.length != blockSize)
      return Failure(new IllegalBlockSizeException("Expected size 32, got " + block.length))

    val p = block2words(block)

    @tailrec
    def encryptBlockHelper(v: Seq[Long], d: Int): Seq[Long] = {
      if(d == numRounds) {
        /* Apply last round key. */
        (v zip roundKeys.last) map { t ⇒ t._1 + t._2 }
      } else {
        /* Add round key every 4th round */
        val e = if(d % 4 == 0) {
          val k = roundKeys(d / 4)
          for(i <- (0 until numWords)) yield v(i) + k(i)
        } else {
          v
        }

        /* Apply mix function */
        val rot = rotations(d % 8)
        val f = (for(i <- (0 until numWords by 2)) yield mix(e(i), e(i + 1), rot(i / 2))).flatten

        /* Apply permutation */
        val vPlus = for(i <- 0 until numWords) yield f(permutation(i))

        encryptBlockHelper(vPlus, d + 1)
      }
    }

    val c = encryptBlockHelper(p, 0)
    Success(words2block(c))
  }

  def decryptBlock(block: Seq[Byte]): Try[Seq[Byte]] = {
    if(block.length != blockSize)
      return Failure(new IllegalBlockSizeException("Expected size 32, got " + block.length))

    @tailrec
    def decryptBlockHelper(v: Seq[Long], d: Int): Seq[Long] = {
      if(d < 0) {
        v
      } else {
        /* Reverse permutation. */
        val f = for(i <- (0 until numWords)) yield v(reversePermutation(i))

        /* Reverse mixing. */
        val rot = rotations(d % 8)
        val e = (for(i <- (0 until numWords by 2)) yield unmix(f(i), f(i + 1), rot(i / 2))).flatten

        /* Substract round key every 4th round */
        val vMinus = if(d % 4 == 0) {
          val k = roundKeys(d / 4)
          for(i <- (0 until numWords)) yield e(i) - k(i)
        } else {
          e
        }

        decryptBlockHelper(vMinus, d - 1)
      }
    }

    val c = block2words(block)
    val v = (c zip roundKeys.last) map { t ⇒ t._1 - t._2 }
    val p = decryptBlockHelper(v, numRounds - 1)

    Success(words2block(p))
  }
}

trait Threefish256 extends Threefish[SymmetricKey256] {

  val blockSize = 32

  val numRounds = 72

  val rotations = Seq(
    Seq(14, 16),
    Seq(52, 57),
    Seq(23, 40),
    Seq( 5, 37),
    Seq(25, 33),
    Seq(46, 12),
    Seq(58, 22),
    Seq(32, 32)
  )

  val permutation: Seq[Int] = Seq(0, 3, 2, 1)

  val reversePermutation: Seq[Int] = Seq(0, 3, 2, 1)
}

trait Threefish512 extends Threefish[SymmetricKey512] {

  val blockSize = 64

  val numRounds = 72

  val rotations = Seq(
    Seq(46, 36, 19, 37),
    Seq(33, 27, 14, 42),
    Seq(17, 49, 36, 39),
    Seq(44,  9, 54, 56),
    Seq(39, 30, 34, 24),
    Seq(13, 50, 10, 17),
    Seq(25, 29, 39, 43),
    Seq( 8, 35, 56, 22)
  )

  val permutation: Seq[Int] = Seq(2, 1, 4, 7, 6, 5, 0, 3)

  val reversePermutation: Seq[Int] = Seq(6, 1, 0, 7, 2, 5, 4, 3)
}

trait Threefish1024 extends Threefish[SymmetricKey1024] {

  val blockSize = 128

  val numRounds = 80

  val rotations = Seq(
    Seq(24, 13,  8, 47,  8, 17, 22, 37),
    Seq(38, 19, 10, 55, 49, 18, 23, 52),
    Seq(33,  4, 51, 13, 34, 41, 59, 17),
    Seq( 5, 20, 48, 41, 47, 28, 16, 25),
    Seq(41,  9, 37, 31, 12, 47, 44, 30),
    Seq(16, 34, 56, 51,  4, 53, 42, 41),
    Seq(31, 44, 47, 46, 19, 42, 44, 25),
    Seq( 9, 48, 35, 52, 23, 31, 37, 20)
  )
  val permutation: Seq[Int] = Seq(0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1)

  val reversePermutation: Seq[Int] = Seq(0, 15, 2, 11, 6, 13, 4, 9, 14, 1, 8, 5, 10, 3, 12, 7)
}

object Threefish256 {
  implicit val builder = new CanBuildBlockCipher[Threefish256] {
    def build(parameters: Parameters): Try[Threefish256] = {
      Parameters.checkParam[SymmetricKey256](parameters, 'symmetricKey256) match {
        case Success(k) ⇒ Parameters.checkParam[Seq[Byte]](parameters, 'tweak) match {
          case Success(t) ⇒ Success(new Threefish256 { val key = k; val tweak = t; val params = parameters })
          case Failure(f) ⇒ Failure(f)
        }
        case Failure(f) ⇒ Failure(f)
      }
    }
  }
}

object Threefish512 {
  implicit val builder = new CanBuildBlockCipher[Threefish512] {
    def build(parameters: Parameters): Try[Threefish512] = {
      Parameters.checkParam[SymmetricKey512](parameters, 'symmetricKey512) match {
        case Success(k) ⇒ Parameters.checkParam[Seq[Byte]](parameters, 'tweak) match {
          case Success(t) ⇒ Success(new Threefish512 { val key = k; val tweak = t; val params = parameters })
          case Failure(f) ⇒ Failure(f)
        }
        case Failure(f) ⇒ Failure(f)
      }
    }
  }
}

object Threefish1024 {
  implicit val builder = new CanBuildBlockCipher[Threefish1024] {
    def build(parameters: Parameters): Try[Threefish1024] = {
      Parameters.checkParam[SymmetricKey1024](parameters, 'symmetricKey1024) match {
        case Success(k) ⇒ Parameters.checkParam[Seq[Byte]](parameters, 'tweak) match {
          case Success(t) ⇒ Success(new Threefish1024 { val key = k; val tweak = t; val params = parameters })
          case Failure(f) ⇒ Failure(f)
        }
        case Failure(f) ⇒ Failure(f)
      }
    }
  }
}
