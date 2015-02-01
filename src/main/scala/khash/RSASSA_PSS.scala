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

object RSASSA_PSS {

  def apply(hashFunction: Hash, saltLength: Int, saltGenerator: (Int) ⇒ Seq[Byte] = Random.nextBytes _) = new KeyedHash[RSAKey] {

    private def mgf1(seed: Seq[Byte], length: Int) = {
      val numBlocks = (length.toFloat / hashFunction.length.toFloat).ceil.toInt
      (for(i <- (0 until numBlocks)) yield hashFunction(seed ++ BigInt(i).i2osp(4).get)).flatten.slice(0, length)
    }

    def apply(key: RSAKey): Try[Iteratee[Seq[Byte], Seq[Byte]]] = {
      if(!key.isPrivateKey) return Failure(new KeyedHashException("No private key."))
      Success(hashFunction.apply flatMap { mHash ⇒
        val emLen = key.length
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
        val maskedDB = 0.toByte +: (db xor dbMask).slice(1, dbLen)

        val em = (maskedDB ++ h) :+ 0xbc.toByte

        val k = key
        val cipher = new blockciphers.RSA { val key = k }
        cipher.decryptBlock(em) match {
          case Success(s) ⇒ Iteratee.done(s)
          case Failure(f) ⇒ Iteratee.error(f)
        }
      })
    }

    def verify(hash: Seq[Byte], key: RSAKey): Try[Iteratee[Seq[Byte],Boolean]] = {
      val k = key
      val cipher = new blockciphers.RSA { val key = k }
      val em = cipher.encryptBlock(hash) match {
        case Success(s) ⇒ s
        case Failure(f) ⇒ return Failure(f)
      }

      val emLen = key.length
      val hLen = hashFunction.length
      val sLen = saltLength
      val dbLen = emLen - hLen - 1
      val psLen = dbLen - sLen - 1
      val standardError = new KeyedHashException("Inconsistent")

      if(em.length != emLen || em(emLen - 1) != 0xbc.toByte) return Failure(standardError)
      val maskedDB = em.slice(0, dbLen)
      val h = em.slice(dbLen, dbLen + hLen)
      val dbMask = mgf1(h, dbLen)
      val db = 0.toByte +: (dbMask xor maskedDB).slice(1, dbLen)

      val ps = Seq.fill[Byte](psLen){0.toByte}
      if(db.slice(0, psLen) != ps || db(psLen) != 1.toByte) return Failure(standardError)

      val salt = db.slice(psLen + 1, dbLen)
      Success(hashFunction.apply map { mHash ⇒
        val mTick = Seq.fill[Byte](8){0.toByte} ++ mHash ++ salt
        h == hashFunction(mTick)
      })
    }

    def length = 0
  }
}
