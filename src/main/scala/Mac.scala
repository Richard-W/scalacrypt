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
import play.api.libs.iteratee._
import scala.concurrent.Await
import scala.concurrent.ExecutionContext
import scala.concurrent.duration._
import scala.concurrent.ExecutionContext.Implicits.global

/** Base class for MAC (Message Authentication Code) implementations. */
trait Mac {

  /** Calculates the MAC. */
  def apply(data: Seq[Byte], key: SymmetricKey): Seq[Byte] = {
    val futureMac = Await.result(apply(key).feed(Input.El(data)), Duration.Inf).run
    Await.result(futureMac, Duration.Inf)
  }

  /** Returns an iteratee calculating the MAC. */
  def apply(key: SymmetricKey)(implicit ec: ExecutionContext): Iteratee[Seq[Byte],Seq[Byte]] 

  /** The length in bytes of the MAC. */
  def length: Int
}
