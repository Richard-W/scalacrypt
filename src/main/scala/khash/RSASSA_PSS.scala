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

import scala.util.{ Try, Success, Failure }
import xyz.wiedenhoeft.scalacrypt._
import iteratees._
import blockciphers.RSA

object RSASSA_PSS {

  def apply(hashFunction: Hash = hash.SHA256, saltLength: Int = 32, saltGenerator: (Int) ⇒ Seq[Byte] = Random.nextBytes _) = new KeyedHash[RSAKey] {

    private def mgf1(seed: Seq[Byte], length: Int) = {
      val numBlocks = (length.toFloat / hashFunction.length.toFloat).ceil.toInt
      (for(i <- (0 until numBlocks)) yield hashFunction(seed ++ BigInt(i).i2osp(4).get)).flatten.slice(0, length)
    }

    def apply(key: RSAKey): Try[Iteratee[Seq[Byte], Seq[Byte]]] = {
      if(!key.isPrivateKey) return Failure(new KeyedHashException("No private key."))
      Success(hashFunction.apply flatMap { mHash ⇒
        val emLen = key.length
        val emBits = key.n.bitLength - 1
        val hLen = hashFunction.length
        val sLen = saltLength
        val dbLen = emLen - hLen - 1
        val psLen = dbLen - sLen - 1

        val salt = saltGenerator(saltLength)
        val mTick = Seq.fill[Byte](8){0.toByte} ++ mHash ++ salt
        val h = hashFunction(mTick)
        
        val ps = Seq.fill[Byte](psLen){0.toByte}
        val db = (ps :+ 1.toByte) ++ salt
        val dbMask = mgf1(h, dbLen)

        val wipeBits = 8 * emLen - emBits
        val saveBits = 8 - wipeBits
        var wipeMask = 0.toByte
        for(i <- (0 until saveBits)) {
          wipeMask = (wipeMask | (1.toByte << i).toByte).toByte
        }

        val maskedDB = (db xor dbMask).toArray
        maskedDB(0) = (maskedDB(0) & wipeMask).toByte

        val em = (maskedDB ++ h) :+ 0xbc.toByte

        val cipher = BlockCipher[RSA](Parameters('rsaKey -> key)).get
        cipher.decryptBlock(em) match {
          case Success(s) ⇒ Iteratee.done(s)
          case Failure(f) ⇒ Iteratee.error(f)
        }
      })
    }

    def verify(key: RSAKey, hash: Seq[Byte]): Try[Iteratee[Seq[Byte],Boolean]] = {
      val cipher = BlockCipher[RSA](Parameters('rsaKey -> key)).get
      val em = cipher.encryptBlock(hash) match {
        case Success(s) ⇒ s
        case Failure(f) ⇒ return Failure(f)
      }

      val emLen = key.length
      val emBits = key.n.bitLength - 1
      val hLen = hashFunction.length
      val sLen = saltLength
      val dbLen = emLen - hLen - 1
      val psLen = dbLen - sLen - 1
      val standardError = new KeyedHashException("Inconsistent")

      if(em.length != emLen || em(emLen - 1) != 0xbc.toByte) return Failure(standardError)
      val maskedDB = em.slice(0, dbLen)
      val h = em.slice(dbLen, dbLen + hLen)
      val dbMask = mgf1(h, dbLen)

      val wipeBits = 8 * emLen - emBits
      val saveBits = 8 - wipeBits
      var wipeMask = 0.toByte
      for(i <- (0 until saveBits)) {
        wipeMask = (wipeMask | (1.toByte << i).toByte).toByte
      }

      val db = (dbMask xor maskedDB).toArray
      db(0) = (db(0) & wipeMask).toByte

      val ps = Seq.fill[Byte](psLen){0.toByte}
      if(db.slice(0, psLen).toSeq != ps || db(psLen) != 1.toByte) return Failure(standardError)

      val salt = db.slice(psLen + 1, dbLen).toSeq
      Success(hashFunction.apply map { mHash ⇒
        val mTick = Seq.fill[Byte](8){0.toByte} ++ mHash ++ salt
        h == hashFunction(mTick)
      })
    }

    def length = 0
  }
}
