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

/** Describes a block cipher mode of operation like ECB or CBC.
  *
  * Each of the methods below gets a state and returns a state. The
  * state is propagated like this: pre* ⇒ post* ⇒ pre*. On the first
  * block pre* receives the None object as the state.
  */
trait BlockCipherMode {

  /** Parameters used to construct this cipher. */
  def params: Parameters

  /** Process the block before it is encrypted. */
  def preEncryptBlock(block: Seq[Byte], state: Option[Any]): (Seq[Byte], Option[Any])

  /** Process the block after it was encrypted. */
  def postEncryptBlock(block: Seq[Byte], state: Option[Any]): (Seq[Byte], Option[Any])

  /** Process the block before it is decrypted. */
  def preDecryptBlock(block: Seq[Byte], state: Option[Any]): (Seq[Byte], Option[Any])

  /** Process the block after it was decrypted. */
  def postDecryptBlock(block: Seq[Byte], state: Option[Any]): (Seq[Byte], Option[Any])
}

abstract class CanBuildBlockCipherMode[A <: BlockCipherMode] {

  def build(params: Parameters): Try[A]
}

object BlockCipherMode {

  def apply[A <: BlockCipherMode : CanBuildBlockCipherMode](params: Parameters)(implicit builder: CanBuildBlockCipherMode[A]) =
    builder.build(params)
}
