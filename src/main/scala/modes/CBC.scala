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
package xyz.wiedenhoeft.scalacrypt.modes

import xyz.wiedenhoeft.scalacrypt._

trait CBC extends BlockCipherMode {

  import scala.language.implicitConversions

  def iv: Seq[Byte]

  def preEncryptBlock(block: Seq[Byte], state: Option[Any]): (Seq[Byte], Option[Any]) = {
    val prev: Seq[Byte] = state match {
      // Use the previous ciphertext block.
      case Some(s) ⇒
      s.asInstanceOf[Seq[Byte]]

      // First block. Use the IV.
      case _ ⇒
      iv
    }

    // Xor the previous ciphertext block/IV to the cleartext block.
    (block xor prev, None)
  }

  def postEncryptBlock(block: Seq[Byte], state: Option[Any]): (Seq[Byte], Option[Any]) = {
    // Save the ciphertext for use in preEncryptBlock.
    (block, Some(block))
  }

  def preDecryptBlock(block: Seq[Byte], state: Option[Any]): (Seq[Byte], Option[Any]) = {
    state match {
      // Supply previous ciphertext for xoring and save ciphertext.
      case Some(s) ⇒
      (block, Some((s.asInstanceOf[Seq[Byte]], block)))

      // First Block. Supply IV for xoring and save ciphertext.
      case _ ⇒
      (block, Some((iv, block)))
    }
  }

  def postDecryptBlock(block: Seq[Byte], state: Option[Any]): (Seq[Byte], Option[Any]) = {
    // Tuple contains previous and current ciphertext block.
    val tuple = state.get.asInstanceOf[(Seq[Byte],Seq[Byte])]
    
    // Xor decrypted block with previous ciphertext block. Set state to current ciphertext.
    (block xor tuple._1, Some(tuple._2))
  }
}
