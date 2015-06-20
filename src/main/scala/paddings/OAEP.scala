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

/**
 * Optimal asymmetric encryption padding as defined in PKCS#1 v2.1
 *
 * Block (length k)
 * 0    1 2 3 4 ... hLen hlen+1 ... k
 * -----------------------------
 * 0x00 ------Seed------ ------DB----
 *
 * k=16
 * hlen=5
 * 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
 * 0 s s s s s d d d d  d  d  d  d  d  d
 *
 * DB (length k - hLen - 1)
 * 0 1 2 ... hlen-1 hlen ... k-hLen-1
 * ----------------------------------
 * ------lHash----- ------mPart------
 *
 * k=16
 * hlen=5
 * 0 1 2 3 4 5 6 7 8 9 10
 * h h h h h m m m m m  m
 */

sealed trait OAEP extends BlockPadding {

  /** Hash function. */
  def hashFunction: Hash

  private def mgf(seed: Seq[Byte], length: Int) = {
    val numBlocks = (length.toFloat / hashFunction.length.toFloat).ceil.toInt
    (for (i <- (0 until numBlocks)) yield hashFunction(seed ++ BigInt(i).i2osp(4).get)).flatten.slice(0, length)
  }

  /** Optional label that can be verified during decryption */
  def label: Seq[Byte] = Seq[Byte]()

  /** Function that generates a seed of the given length. */
  def seedGenerator: (Int) ⇒ Seq[Byte]

  /** Hash of the label. */
  lazy val labelHash = hashFunction(label)

  def pad(data: Iterator[Seq[Byte]], blockSize: Int): Iterator[Seq[Byte]] = new Iterator[Seq[Byte]] {
    var buffer = Seq[Byte]()
    val maxMessageLength = blockSize - 2 * hashFunction.length - 2

    def hasNext = data.hasNext || buffer.length > 0

    def next: Seq[Byte] = {
      while (buffer.length < maxMessageLength && data.hasNext) buffer = buffer ++ data.next

      val message = if (buffer.length > maxMessageLength) {
        val rv = buffer
        buffer = buffer.slice(maxMessageLength, buffer.length)
        rv
      } else {
        val rv = buffer
        buffer = Seq[Byte]()
        rv
      }

      val seed = seedGenerator(hashFunction.length)
      val db = (labelHash ++ (Seq.fill[Byte](maxMessageLength - message.length) { 0.toByte }) :+ 1.toByte) ++ message

      val dbMask = mgf(seed, db.length)
      val maskedDB = db xor dbMask

      val seedMask = mgf(maskedDB, seed.length)
      val maskedSeed = seed xor seedMask

      (0.toByte +: maskedSeed) ++ maskedDB
    }
  }

  def unpad(data: Iterator[Seq[Byte]], blockSize: Int): Iterator[Try[Seq[Byte]]] = new Iterator[Try[Seq[Byte]]] {

    def hasNext = data.hasNext

    def next: Try[Seq[Byte]] = {
      val block = data.next
      if (block.length != blockSize)
        return Failure(new IllegalBlockSizeException("Unpad needs blocks of correct length."))

      /* Never specify what went wrong exactly. */
      val standardError = Some(new BadPaddingException("Invalid OAEP"))
      var error: Option[Exception] = None

      if (block(0) != 0.toByte) {
        error = standardError
      }
      val maskedSeed = block.slice(1, hashFunction.length + 1)
      val maskedDB = block.slice(hashFunction.length + 1, blockSize)

      val seedMask = mgf(maskedDB, maskedSeed.length)
      val seed = maskedSeed xor seedMask

      val dbMask = mgf(seed, maskedDB.length)
      val db = maskedDB xor dbMask

      val dbLabel = db.slice(0, hashFunction.length)
      if (dbLabel != labelHash) {
        error = standardError
      }

      val dbPaddedMessage = db.slice(hashFunction.length, db.length)
      var index = 0
      var indexInPadding = true
      var message = Seq[Byte]()

      // This is overly complicated, but continuing on error
      // makes side channel attacks to get the specific padding
      // error much harder and unreliable.
      while (index < dbPaddedMessage.length && indexInPadding) {
        val digit = dbPaddedMessage(index)
        if (digit != 0.toByte) {
          if (digit == 1.toByte) {
            indexInPadding = false
            message = dbPaddedMessage.slice(index + 1, dbPaddedMessage.length)
          } else {
            error = standardError
          }
        }
        index += 1
      }

      error match {
        case Some(e) ⇒
          Failure(e)

        case _ ⇒
          Success(message)
      }
    }
  }
}

object OAEP {

  implicit val builder = new CanBuildBlockPadding[OAEP] {
    def build(parameters: Parameters): Try[OAEP] = {
      val h = Parameters.checkParam[Hash](parameters, 'hash) match {
        case Success(hash) ⇒ hash
        case Failure(f) ⇒ return Failure(f)
      }
      val lbl = Parameters.checkParam[Seq[Byte]](parameters, 'label) match {
        case Success(label) ⇒ label
        case Failure(f) ⇒ return Failure(f)
      }
      val gen = Parameters.checkParam[(Int) ⇒ Seq[Byte]](parameters, 'generator) match {
        case Success(generator) ⇒ generator
        case Failure(f) ⇒ return Failure(f)
      }
      Success(new OAEP {
        val hashFunction = h
        override val label = lbl
        val seedGenerator = gen
        val params = parameters
      })
    }
  }
}
