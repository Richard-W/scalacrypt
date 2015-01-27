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

import iteratees._

trait Hash {
  
  /** Returns an iteratee that digests its input to a hash. */
  def apply: Iteratee[Seq[Byte], Seq[Byte]]

  /** Digests a given sequence of bytes. */
  def apply(data: Seq[Byte]): Seq[Byte] = apply.fold(Element(data)).run.get

  /** Length of the resulting hash. */
  def length: Int
}
