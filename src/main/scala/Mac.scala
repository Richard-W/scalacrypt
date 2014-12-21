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

import javax.crypto.spec.SecretKeySpec
import scala.util.{ Try, Success, Failure }

/** Base class for MAC (Message Authentication Code) implementations. */
trait Mac {

  /** Calculates the MAC. */
  def apply(data: Seq[Byte], key: SymmetricKey): Seq[Byte]

  /** The length in bytes of the MAC. */
  def length: Int
}

/** Exception that is thrown when a Mac fails somehow. */
class MacException(message: String) extends Exception(message)

/** Base class for MACs implemented in javax.crypto.Mac. */
class JavaMac(algorithm: String) extends Mac {

  def apply(data: Seq[Byte], key: SymmetricKey): Seq[Byte] = {
    if(key.length == 0) {
      throw new MacException("Illegal key length.")
    }

    val k = new SecretKeySpec(key.bytes.toArray, algorithm)
    val mac = javax.crypto.Mac.getInstance(algorithm)

    mac.init(k)
    mac.doFinal(data.toArray)
  }

  def length: Int = {
    javax.crypto.Mac.getInstance(algorithm).getMacLength
  }
}

/** HMAC-SHA1 implementation of Mac. */
object HmacSHA1 extends JavaMac("HmacSHA1")

/** HMAC-SHA256 implementation of Mac. */
object HmacSHA256 extends JavaMac("HmacSHA256")
