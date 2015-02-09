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

import scala.util.{ Try, Success, Failure }

/** Represents a combination of cryptographic primitives to implement
  * a block cipher that can be used on arbitrary iterators.
  */
class BlockCipherSuite[KeyType <: Key](val cipher: BlockCipher[KeyType], val mode: BlockCipherMode, val padding: BlockPadding) {

  private def tryIteratorToTry(it: Iterator[Try[Seq[Byte]]]) = it.foldLeft[Try[Seq[Byte]]](Success(Seq())) { (a, b) ⇒
    if(a.isFailure) a
    else if(b.isFailure) b
    else Success(a.get ++ b.get)
  }

  val blockSize = cipher.blockSize

  /** The combined parameters of cipher, mode and padding.
    *
    * They are merged in the following order overwriting conflicting keys:
    * 1. padding
    * 2. mode
    * 3. cipher
    */
  lazy val params: Parameters = padding.params ++ (mode.params ++ cipher.params)

  def encrypt(input: Seq[Byte]): Try[Seq[Byte]] = tryIteratorToTry(encrypt(Iterator(input)))

  def decrypt(input: Seq[Byte]): Try[Seq[Byte]] = tryIteratorToTry(decrypt(Iterator(input)))

  def encrypt(input: Iterator[Seq[Byte]]): Iterator[Try[Seq[Byte]]] = new Iterator[Try[Seq[Byte]]] {
    // Pad the input and seperate it into blocks.
    val blocks = padding.pad(input, blockSize)

    // Saves the state between blocks.
    var interState: Option[Any] = None

    // If there was a failure.
    var fail = false

    def hasNext = blocks.hasNext && !fail

    def next = {
      // Preprocess block.
      val (pre, preState) = mode.preEncryptBlock(blocks.next, interState)

      // Encrypt block.
      cipher.encryptBlock(pre) match {
        case Failure(f) ⇒
        fail = true
        Failure(f)

        case Success(enc) ⇒
        // Postprocess block.
        val (post, postState) = mode.postEncryptBlock(enc, preState)
        // Save state and return.
        interState = postState
        Success(post)
      }
    }
  }

  def decrypt(input: Iterator[Seq[Byte]]): Iterator[Try[Seq[Byte]]] = {
    val decryptIterator = new Iterator[Try[Seq[Byte]]] {

      var fail = false
      var buffer = Seq[Byte]()
      var interState: Option[Any] = None

      def hasNext = (input.hasNext || buffer.length > 0) && !fail

      def next: Try[Seq[Byte]] = {
        // Fill buffer and extract single block.
        while(buffer.length < blockSize && input.hasNext) {
          buffer = buffer ++ input.next
        }
        if(buffer.length < blockSize) {
          fail = true
          return Failure(new IllegalBlockSizeException("Illegal block size encountered."))
        }
        val block = buffer.slice(0, blockSize)
        buffer = buffer.slice(blockSize, buffer.length)

        // Preprocess block.
        val (pre, preState) = mode.preDecryptBlock(block, interState)
        cipher.decryptBlock(pre) match {
          case Failure(f) ⇒
          fail = true
          Failure(f)

          case Success(dec) ⇒
          val (post, postState) = mode.postDecryptBlock(dec, preState)
          interState = postState
          Success(post)
        }
      }
    }

    // Since BlockPadding.unpad only accepts an Iterator[Seq[Byte]] and we have Iterator[Try[Seq[Byte]]]
    // we catch the failures in prepad filter and have an Iterator[Seq[Byte]]. These errors are then
    // given to the user by wrapping the iterator from the depad method in another iterator that
    // monitors these failures.
    var decryptionFailure: Option[Throwable] = None

    val prepadFilter: Iterator[Seq[Byte]] = new Iterator[Seq[Byte]] {

      def hasNext = decryptIterator.hasNext

      def next: Seq[Byte] = {
        decryptIterator.next match {
          case Failure(f) ⇒
          decryptionFailure = Some(f)
          Seq()

          case Success(s) ⇒
          s
        }
      }
    }

    val depadIterator = padding.unpad(prepadFilter, blockSize)

    new Iterator[Try[Seq[Byte]]] {

      var fail = false

      def hasNext = depadIterator.hasNext && !fail

      def next: Try[Seq[Byte]] = {
        val depadOutput = depadIterator.next

        decryptionFailure match {
          case Some(f) ⇒
          fail = true
          Failure(f)

          case _ ⇒
          depadOutput
        }
      }
    }
  }
}
