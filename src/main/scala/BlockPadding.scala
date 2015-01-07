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

/** Represents the padding used to extend the data to the block size of the block cipher. */
trait BlockPadding {

  def blockSize: Int

  /** Takes an iterator of byte sequences and outputs an iterator of blocks for encryption.
    *
    * Each Seq that the returned iterator returns MUST be exactly blockSize long.
    */
  def pad(input: Iterator[Seq[Byte]]): Iterator[Seq[Byte]]

  /** Takes an iterator of blocks and removes the padding.
    *
    * Each Seq that input contains must be exactly blockSize long.
    */
  def unpad(input: Iterator[Seq[Byte]]): Iterator[Try[Seq[Byte]]]
}
