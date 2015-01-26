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
package xyz.wiedenhoeft.scalacrypt.suites

import xyz.wiedenhoeft.scalacrypt._
import scala.util.{ Try, Success, Failure }

object RSA_ECB_OAEP {

  def apply(k: RSAKey, messageLen: Int): Try[BlockCipherSuite[RSAKey] with blockciphers.RSA with paddings.OAEP with modes.ECB] = {
    if(k.length < 64 || messageLen > 32) Failure(new Exception("Invalid parameters"))
    else Success(new BlockCipherSuite[RSAKey] with blockciphers.RSA with paddings.OAEP with modes.ECB {
      lazy val key = k

      lazy val hash1 = hash.SHA256
      lazy val hash2 = hash.SHA256

      lazy val k1 = 32 - messageLen
    })
  }
}
