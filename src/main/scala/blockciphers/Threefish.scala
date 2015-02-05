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

  type Word = Long

  def bytes2word(bytes: Seq[Byte]): Word =
    ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).put(bytes.toArray).getLong(0)

  def word2bytes(word: Word): Seq[Byte] =
    ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(word).array

  def block2words(block: Seq[Byte]): Seq[Word] =
    for(byteWord <- block.grouped(8).toSeq) yield bytes2word(byteWord)

  def words2block(words: Seq[Word]): Seq[Byte] =
    (for(word <- words) yield word2bytes(word)).flatten

  def mix(a: Word, b: Word, r: Int): Seq[Word] = {
    val x = a + b
    val y = ((b << r) | (b >>> (64 - r))) ^ x
    Seq(x, y)
  }

  def unmix(x: Word, y: Word, r: Int): Seq[Word] = {
    val z = y ^ x
    val b = ((z >>> r) | (z << (64 - r)))
    val a = x - b
    Seq(a, b)
  }
}

/** Threefish block cipher. */
trait Threefish[KeyType <: Key] extends BlockCipher[KeyType] {

  import Threefish._

  type Word = Long

  /** The tweak of this block cipher. */
  def tweak: Seq[Byte]

  /** Rotational constants for the cipher. */
  def rotations: Seq[Seq[Int]]

  /** Permutation used by the cipher. */
  def permutate(block: Seq[Word]): Seq[Word]

  /** Reversal of permutate. */
  def reversePermutate(block: Seq[Word]): Seq[Word]

  /** Number of rounds applied. */
  def numRounds: Int

  /** The number of words this cipher processes in one block. */
  lazy val numWords = blockSize / 8

  lazy val tweakWords: Seq[Word] = {
    val words = block2words(tweak)
    words :+ (words(0) ^ words(1))
  }

  lazy val keyWords: Seq[Word] = {
    @tailrec
    def xorSeq(result: Word, list: List[Word]): Word =
      if(list != Nil)
        xorSeq(result ^ list.head, list.tail)
      else
        result

    val words = block2words(key.bytes)
    words :+ xorSeq(0x1BD11BDAA9FC1A22L, words.toList)
  }

  lazy val roundKeys: Seq[Seq[Word]] = {
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

  def applyRound(words: Seq[Word], rotations: Seq[Int], keyOption: Option[Seq[Word]] = None) = {
    val keyed = keyOption match {
      case Some(key) ⇒ for(i <- (0 until numWords)) yield words(i) + key(i)
      case _ ⇒ words
    }
    val mixed = (for(i <- (0 until numWords by 2)) yield mix(keyed(i), keyed(i + 1), rotations(i / 2))).flatten
    permutate(mixed)
  }

  def unapplyRound(words: Seq[Word], rotations: Seq[Int], keyOption: Option[Seq[Word]] = None) = {
    val ordered = reversePermutate(words)
    val unmixed = (for(i <- (0 until numWords by 2)) yield unmix(ordered(i), ordered(i + 1), rotations(i / 2))).flatten
    keyOption match {
      case Some(key) ⇒ for(i <- (0 until numWords)) yield unmixed(i) - key(i)
      case _ ⇒ unmixed
    }
  }

  def encryptBlock(block: Seq[Byte]): Try[Seq[Byte]] = {
    if(block.length != blockSize)
      return Failure(new IllegalBlockSizeException("Expected size 32, got " + block.length))

    @tailrec
    def applyCipher(words: Seq[Word], round: Int): Seq[Word] = {
      if(round == numRounds)
        for(i <- (0 until numWords)) yield words(i) + roundKeys.last(i)
      else {
        val keyOption: Option[Seq[Word]] =
          if(round % 4 == 0)
            Some(roundKeys(round / 4))
          else
            None
        applyCipher(applyRound(words, rotations(round % 8), keyOption), round + 1)
      }
    }
    
    Success(words2block(applyCipher(block2words(block), 0)))
  }

  def decryptBlock(block: Seq[Byte]): Try[Seq[Byte]] = {
    if(block.length != blockSize)
      return Failure(new IllegalBlockSizeException("Expected size 32, got " + block.length))

    @tailrec
    def unapplyCipher(words: Seq[Word], round: Int): Seq[Word] = {
      if(round == numRounds)
        unapplyCipher(for(i <- (0 until numWords)) yield words(i) - roundKeys.last(i), round - 1)
      else if(round < 0)
        words
      else {
        val keyOption: Option[Seq[Word]] =
          if(round % 4 == 0)
            Some(roundKeys(round / 4))
          else
            None
        unapplyCipher(unapplyRound(words, rotations(round % 8), keyOption), round - 1)
      }
    }

    Success(words2block(unapplyCipher(block2words(block), numRounds)))
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

  def permutate(b: Seq[Word]): Seq[Word] =
    Seq(b(0), b(3), b(2), b(1))

  def reversePermutate(b: Seq[Word]): Seq[Word] =
    Seq(b(0), b(3), b(2), b(1))
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

  def permutate(b: Seq[Word]): Seq[Word] =
    Seq(b(2), b(1), b(4), b(7), b(6), b(5), b(0), b(3))

  def reversePermutate(b: Seq[Word]): Seq[Word] =
    Seq(b(6), b(1), b(0), b(7), b(2), b(5), b(4), b(3))
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

  def permutate(b: Seq[Word]): Seq[Word] =
    Seq(b(0), b(9), b(2), b(13), b(6), b(11), b(4), b(15), b(10), b(7), b(12), b(3), b(14), b(5), b(8), b(1))

  def reversePermutate(b: Seq[Word]): Seq[Word] =
    Seq(b(0), b(15), b(2), b(11), b(6), b(13), b(4), b(9), b(14), b(1), b(8), b(5), b(10), b(3), b(12), b(7))
}
