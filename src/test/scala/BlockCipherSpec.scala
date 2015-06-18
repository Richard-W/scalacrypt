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
import blockciphers._
import scala.util.{ Try, Success, Failure }
import scala.reflect._

abstract class BlockCipherSpec[KeyType <: Key : CanGenerateKey, Cipher <: BlockCipher[KeyType] : CanBuildBlockCipher : ClassTag] extends FlatSpec with Matchers {

  /** Basic parameters that are sufficient to construct the cipher.
    *
    * While processing test vectors these also provide a scaffolding
    * to construct the instances.
    */
  def baseParameters: Parameters

  /** Symbol that is used to add the key to the baseParameters. */
  def keySymbol: Symbol

  /** Sets of parameters and whether construction should succeed. */
  def parameterTestVectors: Seq[(Parameters, Boolean)]

  /** Encryption and decryption test vectors: (cleartext, key, ciphertext, additional params) */
  def testVectors: Seq[(Seq[Byte], KeyType, Seq[Byte], Option[Parameters])]

  val cipherName = classTag[Cipher].runtimeClass.getName.split('.').last

  cipherName should "be buildable using type classes." in {
    BlockCipher[Cipher](baseParameters).get
  }

  it should "pass the parameter test vectors." in {
    for(vector <- parameterTestVectors) {
      val opt = BlockCipher[Cipher](vector._1)
      if(vector._2) opt shouldBe a [Success[_]]
      else opt shouldBe a [Failure[_]]
    }
  }

  it should "be able to encrypt and decrypt a random bytestring." in {
    val cipher = BlockCipher[Cipher](baseParameters ++ Parameters(keySymbol -> Key.generate[KeyType])).get
    val m = Random.nextBytes(cipher.blockSize)
    val c = cipher.encryptBlock(m).get
    cipher.decryptBlock(c).get should be (m)
  }

  it should "pass the encryption test vectors." in {
    for(vector <- testVectors) {
      val m = vector._1
      val k = vector._2
      val c = vector._3
      val pOpt = vector._4

      val params = baseParameters ++ Parameters(keySymbol -> k) ++ (if(pOpt.isDefined) pOpt.get else Parameters())
      val cipher = BlockCipher[Cipher](params).get
      cipher.encryptBlock(m).get should be (c)
      cipher.decryptBlock(c).get should be (m)
    }
  }

  it should "fail on invalid block sizes." in {
    val cipher = BlockCipher[Cipher](baseParameters ++ Parameters(keySymbol -> Key.generate[KeyType])).get
    cipher.encryptBlock(Random.nextBytes(cipher.blockSize - 1)) shouldBe a [Failure[_]]
    cipher.decryptBlock(Random.nextBytes(cipher.blockSize - 1)) shouldBe a [Failure[_]]
    cipher.encryptBlock(Random.nextBytes(cipher.blockSize + 1)) shouldBe a [Failure[_]]
    cipher.decryptBlock(Random.nextBytes(cipher.blockSize + 1)) shouldBe a [Failure[_]]
  }
}

class AES128Spec extends BlockCipherSpec[SymmetricKey128, AES128] {

  val baseParameters = Parameters('symmetricKey128 -> Key.generate[SymmetricKey128])
  val keySymbol = 'symmetricKey128
  val parameterTestVectors = Seq(
    (Parameters('symmetricKey256 -> Key.generate[SymmetricKey256]), false),
    (Parameters('symmetricKey128 -> Key.generate[SymmetricKey192]), false)
  )

  val defaultKey = (Seq(
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
  ) map { _.toByte }).toKey[SymmetricKey128].get

  val testVectors = Seq(
    (
      Seq(0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a) map { _.toByte },
      defaultKey,
      Seq(0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97) map { _.toByte },
      None
    ), (
      Seq(0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51) map { _.toByte },
      defaultKey,
      Seq(0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d, 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf) map { _.toByte },
      None
    ), (
      Seq(0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef) map { _.toByte },
      defaultKey,
      Seq(0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23, 0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88) map { _.toByte },
      None
    ), (
      Seq(0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10) map { _.toByte },
      defaultKey,
      Seq(0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4) map { _.toByte },
      None
    )
  )
}

class AES192Spec extends BlockCipherSpec[SymmetricKey192, AES192] {
  val baseParameters = Parameters('symmetricKey192 -> Key.generate[SymmetricKey192])
  val keySymbol = 'symmetricKey192

  val parameterTestVectors = Seq(
    (Parameters('symmetricKey256 -> Key.generate[SymmetricKey256]), false),
    (Parameters('symmetricKey192 -> Key.generate[SymmetricKey1024]), false)
  )

  val testVectors = Seq()
}

class AES256Spec extends BlockCipherSpec[SymmetricKey256, AES256] {
  val baseParameters = Parameters('symmetricKey256 -> Key.generate[SymmetricKey256])
  val keySymbol = 'symmetricKey256

  val parameterTestVectors = Seq(
    (Parameters('symmetricKey128 -> Key.generate[SymmetricKey128]), false),
    (Parameters('symmetricKey256 -> Key.generate[SymmetricKey128]), false)
  )

  val testVectors = Seq()
}

class Threefish256Spec extends BlockCipherSpec[SymmetricKey256, Threefish256] {
  val baseParameters = Parameters('symmetricKey256 -> Key.generate[SymmetricKey256], 'tweak -> (0 until 16 map { _.toByte }))
  val keySymbol = 'symmetricKey256
  val tweak = (0 until 16) map { _.toByte }

  val parameterTestVectors = Seq(
    (Parameters('symmetricKey128 -> Key.generate[SymmetricKey128], 'tweak -> tweak), false),
    (Parameters('symmetricKey256 -> Key.generate[SymmetricKey1024], 'tweak -> tweak), false),
    (Parameters('symmetricKey256 -> Key.generate[SymmetricKey256], 'tweak -> (0 until 15 map { _.toByte })), false)
  )

  val testVectors = Seq()
}

class Threefish512Spec extends BlockCipherSpec[SymmetricKey512, Threefish512] {
  val baseParameters = Parameters('symmetricKey512 -> Key.generate[SymmetricKey512], 'tweak -> (0 until 16 map { _.toByte }))
  val keySymbol = 'symmetricKey512
  val tweak = (0 until 16) map { _.toByte }

  val parameterTestVectors = Seq(
    (Parameters('symmetricKey256 -> Key.generate[SymmetricKey256], 'tweak -> tweak), false),
    (Parameters('symmetricKey512 -> Key.generate[SymmetricKey1024], 'tweak -> tweak), false),
    (Parameters('symmetricKey512 -> Key.generate[SymmetricKey512], 'tweak -> (0 until 15 map { _.toByte })), false)
  )

  val testVectors = Seq()
}

class Threefish1024Spec extends BlockCipherSpec[SymmetricKey1024, Threefish1024] {
  val baseParameters = Parameters('symmetricKey1024 -> Key.generate[SymmetricKey1024], 'tweak -> (0 until 16 map { _.toByte }))
  val keySymbol = 'symmetricKey1024
  val tweak = (0 until 16) map { _.toByte }

  val parameterTestVectors = Seq(
    (Parameters('symmetricKey256 -> Key.generate[SymmetricKey256], 'tweak -> tweak), false),
    (Parameters('symmetricKey1024 -> Key.generate[SymmetricKey256], 'tweak -> tweak), false),
    (Parameters('symmetricKey512 -> Key.generate[SymmetricKey512], 'tweak -> (0 until 15 map { _.toByte })), false)
  )

  val testVectors = Seq()
}
