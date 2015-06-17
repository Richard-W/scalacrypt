package xyz.wiedenhoeft.scalacrypt

import scala.util.{ Try, Success, Failure }

sealed trait RSAPrivateKeyPart

/** A private key that only holds the private exponent. */
final case class RSAPrivateExponentKeyPart(d: BigInt) extends RSAPrivateKeyPart

/** A private key part that holds parameters for faster application of the private key. */
final case class RSAPrivatePrimeKeyPart(p: BigInt, q: BigInt, dP: BigInt, dQ: BigInt, qInv: BigInt) extends RSAPrivateKeyPart

/** A private key part that holds parameters for faster application of the private key. */
final case class RSAPrivateCombinedKeyPart(d: BigInt, p: BigInt, q: BigInt, dP: BigInt, dQ: BigInt, qInv: BigInt) extends RSAPrivateKeyPart

/** Asymmetric RSA key. */
sealed abstract class RSAKey extends Key {

  /** RSA modulus. */
  val n: BigInt

  /** Public exponent. */
  val e: BigInt

  /** The private part of the key */
  val privateKey: Option[RSAPrivateKeyPart]

  /** Whether this key should be kept secret. */
  def isPrivateKey: Boolean = privateKey.isDefined

  /** Whether it is safe to publish this key. */
  def isPublicKey: Boolean = !isPrivateKey

  /** Returns a RSA key that contains only the public parts. */
  def publicKey: RSAKey = {
    val base = this
    new RSAKey {
      val n = base.n
      val e = base.e
      val privateKey = None
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
    (privateKey match {
      case Some(RSAPrivateExponentKeyPart(d)) ⇒
        f(2, d)
      case Some(RSAPrivatePrimeKeyPart(p, q, dP, dQ, qInv)) ⇒
        f(3, p) ::: f(4, q) ::: f(5, dP) ::: f(6, dQ) ::: f(7, qInv) ::: Nil
      case Some(RSAPrivateCombinedKeyPart(d, p, q, dP, dQ, qInv)) ⇒
        f(2, d) ::: f(3, p) ::: f(4, q) ::: f(5, dP) ::: f(6, dQ) ::: f(7, qInv) ::: Nil
      case None ⇒
        Nil
    }) ::: Nil
  }
}

object RSAKey {

  implicit val mightBuildPublicFromTuple = new MightBuildKey[(Seq[Byte], Seq[Byte]), RSAKey] {
    def tryBuild(keyTuple: (Seq[Byte], Seq[Byte])): Try[RSAKey] = Success(new RSAKey {
      val n = keyTuple._2.os2ip
      val e = keyTuple._1.os2ip
      val privateKey = None
    })
  }

  implicit val mightBuildPrivateFromTuple = new MightBuildKey[(Seq[Byte], Seq[Byte], Seq[Byte]), RSAKey] {
    def tryBuild(keyTuple: (Seq[Byte], Seq[Byte], Seq[Byte])): Try[RSAKey] = Success(new RSAKey {
      val n = keyTuple._3.os2ip
      val e = keyTuple._1.os2ip
      val privateKey = Some(new RSAPrivateExponentKeyPart(keyTuple._2.os2ip))
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

      val key: Option[RSAPrivateKeyPart] =
        if((2 to 7).map({ map.contains(_) }).filter({ !_ }).length == 0) 
          Some(new RSAPrivateCombinedKeyPart(map(2), map(3), map(4), map(5), map(6), map(7)))
        else if((3 to 7).map({ map.contains(_) }).filter({ !_ }).length == 0) 
          Some(new RSAPrivatePrimeKeyPart(map(3), map(4), map(5), map(6), map(7)))
        else if(map.contains(2))
          Some(new RSAPrivateExponentKeyPart(map(2)))
        else
          None

      if(! map.contains(0) || !map.contains(1)) {
        Failure(new KeyException("Important parameters missing in RSAKey."))
      } else Success(new RSAKey {
        val n = map.get(0).get
        val e = map.get(1).get
        val privateKey = key
      })
    }
  }

  implicit val canGenerateKey = new CanGenerateKey[RSAKey] {
    def generate = new RSAKey {
      val javaKeyPairGenerator = java.security.KeyPairGenerator.getInstance("RSA")
      javaKeyPairGenerator.initialize(4096)
      val javaKeyPair = javaKeyPairGenerator.generateKeyPair
      val javaPubKey = javaKeyPair.getPublic.asInstanceOf[java.security.interfaces.RSAPublicKey]
      val javaPrivKey = javaKeyPair.getPrivate.asInstanceOf[java.security.interfaces.RSAPrivateCrtKey]

      val n = BigInt(javaPubKey.getModulus)
      val e = BigInt(javaPubKey.getPublicExponent)

      // Private key variant 1
      val p = javaPrivKey.getPrimeP
      val q = javaPrivKey.getPrimeQ
      val d = javaPrivKey.getPrivateExponent
      val dP = javaPrivKey.getPrimeExponentP
      val dQ = javaPrivKey.getPrimeExponentQ
      val qInv = javaPrivKey.getCrtCoefficient
      val privateKey = Some(new RSAPrivateCombinedKeyPart(d, p, q, dP, dQ, qInv))
    }
  }
}
