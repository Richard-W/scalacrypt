package xyz.wiedenhoeft.scalacrypt

import scala.util.{ Try, Success, Failure }

/** A private key that only holds the private exponent. */
final class RSAPrivateKeyV1(val d: BigInt) { }

/** A private key part that holds parameters for faster application of the private key. */
final class RSAPrivateKeyV2(val p: BigInt, val q: BigInt, val dP: BigInt, val dQ: BigInt, val qInv: BigInt) { }

/** Asymmetric RSA key. */
sealed abstract class RSAKey extends Key {

  /** RSA modulus. */
  val n: BigInt

  /** Public exponent. */
  val e: BigInt

  val privateKey1: Option[RSAPrivateKeyV1]

  val privateKey2: Option[RSAPrivateKeyV2]

  /** Whether this key should be kept secret. */
  def isPrivateKey: Boolean = if(privateKey1.isDefined || privateKey2.isDefined) true else false

  /** Whether it is safe to publish this key. */
  def isPublicKey: Boolean = !isPrivateKey

  /** Returns a RSA key that contains only the public parts. */
  def publicKey: RSAKey = {
    val base = this
    new RSAKey {
      val n = base.n
      val e = base.e
      val privateKey1 = None
      val privateKey2 = None
    }
  }

  def length = (n.bitLength.toFloat / 8.0).ceil.toInt

  def bytes: Seq[Byte] = {
    def f(identifier: Int, value: BigInt): List[Byte] = {
      val byteArray: List[Byte] = value.toByteArray.toList
      val lengthBytes: List[Byte] = java.nio.ByteBuffer.allocate(4).putInt(byteArray.length).array.toList
      identifier.toByte :: lengthBytes ::: byteArray ::: Nil
    }

    f(0, n) ::: f(1, e) :::
      (if(privateKey1.isDefined) f(2, privateKey1.get.d) else Nil) :::
      (if(privateKey2.isDefined) {
        val k2 = privateKey2.get
        f(3, k2.p) :::
          f(4, k2.q) :::
          f(5, k2.dP) :::
          f(6, k2.dQ) :::
          f(7, k2.qInv) :::
          Nil
      } else Nil)
  }
}

object RSAKey {

  implicit val mightBuildPublicFromTuple = new MightBuildKey[(Seq[Byte], Seq[Byte]), RSAKey] {
    def tryBuild(keyTuple: (Seq[Byte], Seq[Byte])): Try[RSAKey] = Success(new RSAKey {
      val n = keyTuple._2.os2ip
      val e = keyTuple._1.os2ip
      val privateKey1 = None
      val privateKey2 = None
    })
  }

  implicit val mightBuildPrivateFromTuple = new MightBuildKey[(Seq[Byte], Seq[Byte], Seq[Byte]), RSAKey] {
    def tryBuild(keyTuple: (Seq[Byte], Seq[Byte], Seq[Byte])): Try[RSAKey] = Success(new RSAKey {
      val n = keyTuple._3.os2ip
      val e = keyTuple._1.os2ip
      val privateKey1 = Some(new RSAPrivateKeyV1(keyTuple._2.os2ip))
      val privateKey2 = None
    })
  }

  implicit val mightBuildFromBytes = new MightBuildKey[Seq[Byte], RSAKey] {

    def tryBuild(keyBytes: Seq[Byte]): Try[RSAKey] = {
      def createMap(map: Map[Int, BigInt], bytes: Seq[Byte]): Try[Map[Int, BigInt]] = {
        if(bytes.length == 0) {
          Success(Map[Int, BigInt]())
        } else if(bytes.length < 5) {
          Failure(new KeyException("Invalid length of RSA key."))
        } else {
          val identifier = bytes(0)
          val length = java.nio.ByteBuffer.allocate(4).put(bytes.slice(1, 5).toArray).getInt(0)
          val withoutHeader = bytes.slice(5, bytes.length)
          if(withoutHeader.length < length) {
            Failure(new KeyException("Invalid length of RSA key."))
          } else {
            val data = withoutHeader.slice(0, length)
            val newMap = map + ((identifier.toInt, BigInt(data.toArray)))
            createMap(newMap, withoutHeader.slice(length, withoutHeader.length)) match {
              case Success(rMap) ⇒
              Success(newMap ++ rMap)

              case f: Failure[_] ⇒
              f
            }
          }
        }
      }

      val map: Map[Int, BigInt] = createMap(Map[Int, BigInt](), keyBytes) match {
        case Success(m) ⇒
        m

        case f: Failure[_] ⇒
        return f.asInstanceOf[Try[RSAKey]]
      }

      val key1: Option[RSAPrivateKeyV1] = if(map.contains(2))
        Some(new RSAPrivateKeyV1(map(2)))
      else
        None

      val key2: Option[RSAPrivateKeyV2] = if((3 to 7).map({ map.contains(_) }).filter({ !_ }).length == 0)
        Some(new RSAPrivateKeyV2(map(3), map(4), map(5), map(6), map(7)))
      else
        None

      if(! map.contains(0) || !map.contains(1)) {
        Failure(new KeyException("Important parameters missing in RSAKey."))
      } else Success(new RSAKey {
        val n = map.get(0).get
        val e = map.get(1).get
        val privateKey1 = key1
        val privateKey2 = key2
      })
    }
  }

  implicit val canGenerateKey = new CanGenerateKey[RSAKey] {
    def generate = new RSAKey {
      val random = new scala.util.Random(new java.security.SecureRandom)

      val p = BigInt.probablePrime(2048, random)
      val q = BigInt.probablePrime(2048, random)

      // Public Key
      val n = p * q
      val e = BigInt(65537)

      // Private key variant 1
      val ϕ = (p - 1) * (q - 1)
      val d = e modInverse ϕ
      val privateKey1 = Some(new RSAPrivateKeyV1(d))

      // Private key variant 2
      val dP = d mod (p - 1)
      val dQ = d mod (q - 1)
      val qInv = q modInverse p
      val privateKey2 = Some(new RSAPrivateKeyV2(p, q, dP, dQ, qInv))
    }
  }
}
