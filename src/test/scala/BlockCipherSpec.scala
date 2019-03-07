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

abstract class BlockCipherSpec[KeyType <: Key: CanGenerateKey, Cipher <: BlockCipher[KeyType]: CanBuildBlockCipher: ClassTag] extends FlatSpec with Matchers {

  /**
   * Basic parameters that are sufficient to construct the cipher.
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

  /** Block size this cipher should have */
  def blockSize: Int

  /**
   * When encrypting and decrypting a random block this is prepended to the random block.
   *
   * It is needed for example by RSA where the numerical message representation must be less than
   * the modulus of the key.
   */
  def firstBytesOfRandomBlock: Seq[Byte] = Seq()

  val cipherName = classTag[Cipher].runtimeClass.getName.split('.').last

  cipherName should "be buildable using type classes." in {
    BlockCipher[Cipher](baseParameters).get
  }

  it should "pass the parameter test vectors." in {
    for (vector <- parameterTestVectors) {
      val opt = BlockCipher[Cipher](vector._1)
      if (vector._2) opt shouldBe a[Success[_]]
      else opt shouldBe a[Failure[_]]
    }
  }

  it should "be able to encrypt and decrypt a random bytestring." in {
    val cipher = BlockCipher[Cipher](baseParameters).get
    val m = firstBytesOfRandomBlock ++ Random.nextBytes(cipher.blockSize - firstBytesOfRandomBlock.length)
    val c = cipher.encryptBlock(m).get
    cipher.decryptBlock(c).get should be(m)
  }

  it should "pass the encryption test vectors." in {
    for (vector <- testVectors) {
      val m = vector._1
      val k = vector._2
      val c = vector._3
      val pOpt = vector._4

      val params = baseParameters ++ Parameters(keySymbol -> k) ++ (if (pOpt.isDefined) pOpt.get else Parameters())
      val cipher = BlockCipher[Cipher](params).get
      cipher.encryptBlock(m).get should be(c)
      cipher.decryptBlock(c).get should be(m)
    }
  }

  it should "fail on invalid block sizes." in {
    val cipher = BlockCipher[Cipher](baseParameters).get
    cipher.encryptBlock(Random.nextBytes(cipher.blockSize - 1)) shouldBe a[Failure[_]]
    cipher.decryptBlock(Random.nextBytes(cipher.blockSize - 1)) shouldBe a[Failure[_]]
    cipher.encryptBlock(Random.nextBytes(cipher.blockSize + 1)) shouldBe a[Failure[_]]
    cipher.decryptBlock(Random.nextBytes(cipher.blockSize + 1)) shouldBe a[Failure[_]]
  }

  it should "have the correct block size" in {
    val cipher = BlockCipher[Cipher](baseParameters).get
    cipher.blockSize should be(blockSize)
  }
}

class AES128Spec extends BlockCipherSpec[SymmetricKey128, AES128] {

  val baseParameters = Parameters('symmetricKey128 -> Key.generate[SymmetricKey128])
  val keySymbol = 'symmetricKey128
  val blockSize = 16

  val parameterTestVectors = Seq(
    (Parameters('symmetricKey256 -> Key.generate[SymmetricKey256]), false),
    (Parameters('symmetricKey128 -> Key.generate[SymmetricKey192]), false))

  val defaultKey = (Seq(
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c) map { _.toByte }).toKey[SymmetricKey128].get

  val testVectors = Seq(
    (
      Seq(0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a) map { _.toByte },
      defaultKey,
      Seq(0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97) map { _.toByte },
      None), (
      Seq(0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51) map { _.toByte },
      defaultKey,
      Seq(0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d, 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf) map { _.toByte },
      None), (
      Seq(0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef) map { _.toByte },
      defaultKey,
      Seq(0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23, 0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88) map { _.toByte },
      None), (
      Seq(0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10) map { _.toByte },
      defaultKey,
      Seq(0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4) map { _.toByte },
      None))
}

class AES192Spec extends BlockCipherSpec[SymmetricKey192, AES192] {
  val baseParameters = Parameters('symmetricKey192 -> Key.generate[SymmetricKey192])
  val keySymbol = 'symmetricKey192
  val blockSize = 16

  val parameterTestVectors = Seq(
    (Parameters('symmetricKey256 -> Key.generate[SymmetricKey256]), false),
    (Parameters('symmetricKey192 -> Key.generate[SymmetricKey1024]), false))

  val testVectors = Seq()
}

class AES256Spec extends BlockCipherSpec[SymmetricKey256, AES256] {
  val baseParameters = Parameters('symmetricKey256 -> Key.generate[SymmetricKey256])
  val keySymbol = 'symmetricKey256
  val blockSize = 16

  val parameterTestVectors = Seq(
    (Parameters('symmetricKey128 -> Key.generate[SymmetricKey128]), false),
    (Parameters('symmetricKey256 -> Key.generate[SymmetricKey128]), false))

  val testVectors = Seq()
}

class Threefish256Spec extends BlockCipherSpec[SymmetricKey256, Threefish256] {
  val baseParameters = Parameters('symmetricKey256 -> Key.generate[SymmetricKey256], 'tweak -> (0 until 16 map { _.toByte }))
  val keySymbol = 'symmetricKey256
  val tweak = (0 until 16) map { _.toByte }
  val blockSize = 32

  val parameterTestVectors = Seq(
    (Parameters('symmetricKey128 -> Key.generate[SymmetricKey128], 'tweak -> tweak), false),
    (Parameters('symmetricKey256 -> Key.generate[SymmetricKey1024], 'tweak -> tweak), false),
    (Parameters('symmetricKey256 -> Key.generate[SymmetricKey256], 'tweak -> (0 until 15 map { _.toByte })), false))

  val testVectors = Seq()
}

class Threefish512Spec extends BlockCipherSpec[SymmetricKey512, Threefish512] {
  val baseParameters = Parameters('symmetricKey512 -> Key.generate[SymmetricKey512], 'tweak -> (0 until 16 map { _.toByte }))
  val keySymbol = 'symmetricKey512
  val tweak = (0 until 16) map { _.toByte }
  val blockSize = 64

  val parameterTestVectors = Seq(
    (Parameters('symmetricKey256 -> Key.generate[SymmetricKey256], 'tweak -> tweak), false),
    (Parameters('symmetricKey512 -> Key.generate[SymmetricKey1024], 'tweak -> tweak), false),
    (Parameters('symmetricKey512 -> Key.generate[SymmetricKey512], 'tweak -> (0 until 15 map { _.toByte })), false))

  val testVectors = Seq()
}

class Threefish1024Spec extends BlockCipherSpec[SymmetricKey1024, Threefish1024] {
  val baseParameters = Parameters('symmetricKey1024 -> Key.generate[SymmetricKey1024], 'tweak -> (0 until 16 map { _.toByte }))
  val keySymbol = 'symmetricKey1024
  val tweak = (0 until 16) map { _.toByte }
  val blockSize = 128

  val parameterTestVectors = Seq(
    (Parameters('symmetricKey256 -> Key.generate[SymmetricKey256], 'tweak -> tweak), false),
    (Parameters('symmetricKey1024 -> Key.generate[SymmetricKey256], 'tweak -> tweak), false),
    (Parameters('symmetricKey512 -> Key.generate[SymmetricKey512], 'tweak -> (0 until 15 map { _.toByte })), false))

  val testVectors = Seq()
}

class RSACrtSpec extends BlockCipherSpec[RSAKey, RSA] {

  val crtKey =
    """ |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
    |1KJvCOgIoxKqFtV+O7c=""".stripMargin.toBase64Bytes.toKey[RSAKey].get

  val baseParameters = Parameters('rsaKey -> crtKey)
  val keySymbol = 'rsaKey
  val blockSize = 512
  override val firstBytesOfRandomBlock = Seq(0, 0, 0, 0) map { _.toByte }

  val parameterTestVectors = Seq(
    (Parameters('symmetricKey256 -> Key.generate[SymmetricKey256]), false),
    (Parameters('rsaKey -> Key.generate[SymmetricKey1024]), false))

  val testVectors = Seq()
}

class RSAExpSpec extends BlockCipherSpec[RSAKey, RSA] {

  val crtKey =
    """ |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
    |1KJvCOgIoxKqFtV+O7c=""".stripMargin.toBase64Bytes.toKey[RSAKey].get

  val expKey = (crtKey.e.toByteArray.toSeq, crtKey.privateKey.get.asInstanceOf[RSAPrivateCombinedKeyPart].d.toByteArray.toSeq, crtKey.n.toByteArray.toSeq).toKey[RSAKey].get

  val baseParameters = Parameters('rsaKey -> expKey)
  val keySymbol = 'rsaKey
  val blockSize = 512
  override val firstBytesOfRandomBlock = Seq(0, 0, 0, 0) map { _.toByte }

  val parameterTestVectors = Seq(
    (Parameters('symmetricKey256 -> Key.generate[SymmetricKey256]), false),
    (Parameters('rsaKey -> Key.generate[SymmetricKey1024]), false))

  val testVectors = Seq()
}
