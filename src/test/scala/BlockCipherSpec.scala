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

import org.scalatest._
import scala.util.{ Try, Success, Failure }
import blockciphers._

class BlockCipherSpec extends FlatSpec with Matchers {

  "BlockCiphers" should "be buildable using type classes." in {
    val params = Parameters(
      'symmetricKey256 -> Key.generate[SymmetricKey256],
      'tweak -> Random.nextBytes(16)
    )

    val aes256 = BlockCipher[AES256](params).get
    aes256 shouldBe a [AES256]

    val threefish256 = BlockCipher[Threefish256](params).get
    threefish256 shouldBe a [Threefish256]

    // 'symmetricKey512 missing
    BlockCipher[Threefish512](params) shouldBe a [Failure[_]]
  }

  they should "check the type of the parameters." in {
    val params = Parameters(
      'symmetricKey256 -> Key.generate[SymmetricKey128]
    )

    BlockCipher[Threefish256](params) shouldBe a [Failure[_]]
  }
}
