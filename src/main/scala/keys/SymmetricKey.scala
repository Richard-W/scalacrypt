package xyz.wiedenhoeft.scalacrypt

import scala.util.{ Try, Success, Failure }

/** A 128 bit symmetric key. */
sealed abstract class SymmetricKey128 extends Key

object SymmetricKey128 {

  implicit val mightBuildKey = new MightBuildKey[Seq[Byte], SymmetricKey128] {

    def tryBuild(keyBytes: Seq[Byte]): Try[SymmetricKey128] = {
      if (keyBytes.length == 128 / 8) {
        Success(new SymmetricKey128Impl(keyBytes))
      } else {
        Failure(new KeyException("Illegal key size. SymmetricKey128 must be 128 bits long."))
      }
    }

    private class SymmetricKey128Impl(val bytes: Seq[Byte]) extends SymmetricKey128 {

      def length: Int = 16
    }
  }

  implicit val canGenerateKey = new CanGenerateKey[SymmetricKey128] {
    def generate = Random.nextBytes(16).toKey[SymmetricKey128].get
  }
}

/** A 192 bit symmetric key. */
sealed abstract class SymmetricKey192 extends Key

object SymmetricKey192 {

  implicit val mightBuildKey = new MightBuildKey[Seq[Byte], SymmetricKey192] {

    def tryBuild(keyBytes: Seq[Byte]): Try[SymmetricKey192] = {
      if (keyBytes.length == 192 / 8) {
        Success(new SymmetricKey192Impl(keyBytes))
      } else {
        Failure(new KeyException("Illegal key size. SymmetricKey192 must be 192 bits long."))
      }
    }

    private class SymmetricKey192Impl(val bytes: Seq[Byte]) extends SymmetricKey192 {

      def length: Int = 24
    }
  }

  implicit val canGenerateKey = new CanGenerateKey[SymmetricKey192] {
    def generate = Random.nextBytes(24).toKey[SymmetricKey192].get
  }
}

/** A 256 bit symmetric key. */
sealed abstract class SymmetricKey256 extends Key

object SymmetricKey256 {

  implicit val mightBuildKey = new MightBuildKey[Seq[Byte], SymmetricKey256] {

    def tryBuild(keyBytes: Seq[Byte]): Try[SymmetricKey256] = {
      if (keyBytes.length == 256 / 8) {
        Success(new SymmetricKey256Impl(keyBytes))
      } else {
        Failure(new KeyException("Illegal key size. SymmetricKey256 must be 256 bits long."))
      }
    }

    private class SymmetricKey256Impl(val bytes: Seq[Byte]) extends SymmetricKey256 {

      def length: Int = 32
    }
  }

  implicit val canGenerateKey = new CanGenerateKey[SymmetricKey256] {
    def generate = Random.nextBytes(32).toKey[SymmetricKey256].get
  }
}

/** A 512 bit symmetric key. */
sealed abstract class SymmetricKey512 extends Key

object SymmetricKey512 {

  implicit val mightBuildKey = new MightBuildKey[Seq[Byte], SymmetricKey512] {

    def tryBuild(keyBytes: Seq[Byte]): Try[SymmetricKey512] = {
      if (keyBytes.length == 512 / 8) {
        Success(new SymmetricKey512Impl(keyBytes))
      } else {
        Failure(new KeyException("Illegal key size. SymmetricKey512 must be 512 bits long."))
      }
    }

    private class SymmetricKey512Impl(val bytes: Seq[Byte]) extends SymmetricKey512 {

      def length: Int = 64
    }
  }

  implicit val canGenerateKey = new CanGenerateKey[SymmetricKey512] {
    def generate = Random.nextBytes(64).toKey[SymmetricKey512].get
  }
}

/** A 1024 bit symmetric key. */
sealed abstract class SymmetricKey1024 extends Key

object SymmetricKey1024 {

  implicit val mightBuildKey = new MightBuildKey[Seq[Byte], SymmetricKey1024] {

    def tryBuild(keyBytes: Seq[Byte]): Try[SymmetricKey1024] = {
      if (keyBytes.length == 1024 / 8) {
        Success(new SymmetricKey1024Impl(keyBytes))
      } else {
        Failure(new KeyException("Illegal key size. SymmetricKey1024 must be 1024 bits long."))
      }
    }

    private class SymmetricKey1024Impl(val bytes: Seq[Byte]) extends SymmetricKey1024 {

      def length: Int = 128
    }
  }

  implicit val canGenerateKey = new CanGenerateKey[SymmetricKey1024] {
    def generate = Random.nextBytes(128).toKey[SymmetricKey1024].get
  }
}

/** A symmetric key of arbitrary length. */
sealed abstract class SymmetricKeyArbitrary extends Key

object SymmetricKeyArbitrary {

  implicit val MightBuildKey = new MightBuildKey[Seq[Byte], SymmetricKeyArbitrary] {

    def tryBuild(keyBytes: Seq[Byte]): Try[SymmetricKeyArbitrary] = {
      Success(new SymmetricKeyArbitraryImpl(keyBytes))
    }

    private class SymmetricKeyArbitraryImpl(val bytes: Seq[Byte]) extends SymmetricKeyArbitrary {

      def length: Int = bytes.length
    }
  }

  implicit val canGenerateKey = new CanGenerateKey[SymmetricKeyArbitrary] {
    def generate = Random.nextBytes(32).toKey[SymmetricKeyArbitrary].get
  }
}
