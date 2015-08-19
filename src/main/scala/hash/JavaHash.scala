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
package xyz.wiedenhoeft.scalacrypt.hash

import xyz.wiedenhoeft.scalacrypt._
import iteratees._
import scala.util.{ Try, Success, Failure }

/** Base class for hash algorithms implemented in javax.security.MessageDigest. */
class JavaHash(algorithm: String, val blockSize: Int) extends Hash {

  def apply: Iteratee[Seq[Byte], Seq[Byte]] = {
    val digest = java.security.MessageDigest.getInstance(algorithm)

    Iteratee.fold[Seq[Byte], java.security.MessageDigest](digest) { (digest, data) ⇒
      val newDigest = digest.clone.asInstanceOf[java.security.MessageDigest]
      newDigest.update(data.toArray)
      Success(newDigest)
    } map {
      digest ⇒ digest.digest
    }
  }

  lazy val length: Int = java.security.MessageDigest.getInstance(algorithm).getDigestLength
}

object MD5 extends JavaHash("MD5", 64)
