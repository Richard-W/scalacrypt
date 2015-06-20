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
import scala.util.{ Try, Success, Failure }

sealed trait ECB extends BlockCipherMode {

  def preEncryptBlock(block: Seq[Byte], state: Option[Any]): (Seq[Byte], Option[Any]) = {
    (block, None)
  }

  def postEncryptBlock(block: Seq[Byte], state: Option[Any]): (Seq[Byte], Option[Any]) = {
    (block, None)
  }

  def preDecryptBlock(block: Seq[Byte], state: Option[Any]): (Seq[Byte], Option[Any]) = {
    (block, None)
  }

  def postDecryptBlock(block: Seq[Byte], state: Option[Any]): (Seq[Byte], Option[Any]) = {
    (block, None)
  }
}

object ECB {

  implicit val builder = new CanBuildBlockCipherMode[ECB] {
    def build(parameters: Parameters) = Success(new ECB { val params = parameters })
  }
}
