/* Copyright 2014 Richard Wiedenhoeft <richard@wiedenhoeft.xyz>
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

abstract class SymmetricBlockCipherSuite[KeyType <: SymmetricKey] extends SymmetricBlockCipher[KeyType] with BlockPadding with BlockCipherMode {

  def encrypt(input: Iterator[Seq[Byte]]): Iterator[Try[Seq[Byte]]] = new Iterator[Try[Seq[Byte]]] {
    // Pad the input and seperate it into blocks.
    val blocks = pad(input)

    // Saves the state between blocks.
    var interState: Option[Any] = None

    // If there was a failure.
    var fail = false

    def hasNext = blocks.hasNext && !fail

    def next = {
      // Preprocess block.
      val (pre, preState) = preEncryptBlock(blocks.next, interState)

      // Encrypt block.
      encryptBlock(pre) match {
        case Failure(f) ⇒
        fail = true
        Failure(f)

        case Success(enc) ⇒
        // Postprocess block.
        val (post, postState) = postEncryptBlock(enc, preState)
        // Save state and return.
        interState = postState
        Success(post)
      }
    }
  }
}
