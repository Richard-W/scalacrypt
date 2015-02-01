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
package xyz.wiedenhoeft.scalacrypt.khash

import xyz.wiedenhoeft.scalacrypt._
import javax.crypto.spec.SecretKeySpec
import scala.util.{ Try, Success, Failure }
import iteratees._

/** Base class for MACs implemented in javax.crypto.Mac.
  *
  * Attention: If the key is empty it is substituted by a single zero-byte.
  */
class JavaMac(algorithm: String) extends KeyedHash[Key] {

  def apply(key: Key): Iteratee[Seq[Byte],Seq[Byte]] = {
    val k: SecretKeySpec = if(key.length != 0) {
      new SecretKeySpec(key.bytes.toArray, algorithm)
    } else {
      new SecretKeySpec(Array(0.toByte), algorithm)
    }
    val mac = javax.crypto.Mac.getInstance(algorithm)

    mac.init(k)
    Iteratee.fold[Seq[Byte],javax.crypto.Mac](mac) { (mac, data) ⇒
      val newMac = mac.clone.asInstanceOf[javax.crypto.Mac]
      newMac.update(data.toArray)
      newMac
    } map {
      mac ⇒ mac.doFinal
    }
  }

  def verify(hash: Seq[Byte], key: Key): Iteratee[Seq[Byte], Boolean] = apply(key) map { _ == hash }

  lazy val length: Int = javax.crypto.Mac.getInstance(algorithm).getMacLength
}

/** HMAC-SHA1 implementation of Mac. */
object HmacSHA1 extends JavaMac("HmacSHA1")

/** HMAC-SHA256 implementation of Mac. */
object HmacSHA256 extends JavaMac("HmacSHA256")
