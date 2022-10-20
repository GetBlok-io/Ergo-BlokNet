package org.ergoplatform.mining

import com.google.common.primitives.{Bytes, Ints, Longs}
import org.bouncycastle.util.BigIntegers
import org.ergoplatform.mining.SNISPGenerator.mu
import org.ergoplatform.mining.difficulty.RequiredDifficulty
import org.ergoplatform.modifiers.history.header.Header
import scorex.crypto.hash.Blake2b256
import scorex.util.ScorexLogging

import scala.annotation.tailrec
import scala.util.Try

class SNISPGenerator(powScheme: AutolykosPowScheme) extends ScorexLogging{
  // Copied from AutolykosPoWScheme.scala
  private def genIndexes(seed: Array[Byte], N: Int): Seq[Int] = {
    val hash = Blake2b256(seed)
    val extendedHash = Bytes.concat(hash, hash.take(3))
    (0 until powScheme.k).map { i =>
      BigInt(1, extendedHash.slice(i, i + 4)).mod(N).toInt
    }
  }.ensuring(_.length == powScheme.k)

  // Copied from AutolykosPoWScheme.scala
  private def genElement(version: Header.Version,
                         m: Array[Byte],
                         pk: Array[Byte], // not used in v2
                         w: Array[Byte], // not used in v2
                         indexBytes: Array[Byte],
                         heightBytes: => Array[Byte] // not used in v1
                        ): BigInt = {
    if (version == 1) {
      // Autolykos v. 1: H(j|M|pk|m|w) (line 5 from the Algo 2 of the spec)
      hashModQ(Bytes.concat(indexBytes, powScheme.M, pk, m, w))
    } else {
      // Autolykos v. 2: H(j|h|M) (line 5 from the Algo 2 of the spec)
      toBigInt(hash(Bytes.concat(indexBytes, heightBytes, powScheme.M)).drop(1))
    }
  }


  // Use total hashes (h*W) divided by target number of shares to create ideal tau
  def idealTau(N: Long, totalHashes: Long): BigInt = powScheme.getB(idealNBits(N, totalHashes))

  // Ideal diff encoded in NBits
  def idealNBits(N: Long, totalHashes: Long): Long = RequiredDifficulty.encodeCompactBits(totalHashes / N)

  // Generate proofs (valid or invalid) for all possible levels
  def generateProofs(hashSet: Seq[BigInt], tau: BigInt, N: Long) = {
    for(i <- 1 to mu) yield
      ShareProof(
        hashSet.filter(_ < (tau * i) / N).take(i),
        tau,
        i,
        N
      )
  }

  def bestProof(proofSet: Seq[ShareProof]): Try[ShareProof] = {
    Try(proofSet.filter(_.isValid).minBy(_.i))
  }

  // Mine for a certain number of nonces in order to create a hash set
  // Modified from AutolykosPoWScheme.scala
  def mineShares(version: Header.Version,
                                 h: Array[Byte],
                                 m: Array[Byte],
                                 sk: BigInt,
                                 x: BigInt,
                                 tau: BigInt,
                                 N: Int,
                                 startNonce: Long,
                                 endNonce: Long): Seq[BigInt] = {
    log.debug(s"Going to check nonces from $startNonce to $endNonce")
    val p1 = groupElemToBytes(genPk(sk))
    val p2 = groupElemToBytes(genPk(x))

    @tailrec
    def loop(i: Long, hashSet: Seq[BigInt] = Seq.empty[BigInt]): Seq[BigInt] = if (i == endNonce) {
      hashSet
    } else {
      if (i % 1000 == 0 && i > 0) println(s"$i nonce tested")
      val nonce = Longs.toByteArray(i)
      val seed = {
        val i = BigIntegers.asUnsignedByteArray(4, BigIntegers.fromUnsignedByteArray(hash(Bytes.concat(m, nonce)).takeRight(8)).mod(BigInt(N).underlying()))
        val f = Blake2b256(Bytes.concat(i, h, powScheme.M)).drop(1)
        Bytes.concat(f, m, nonce)
      }
      val d = {
        val indexes = genIndexes(seed, N)
        toBigInt(hash(indexes.map(i => genElement(version, m, p1, p2, Ints.toByteArray(i), h)).sum.toByteArray))
      }
      if (d <= tau) {
        log.debug(s"Share found at $i")
        loop(i + 1, hashSet ++ Seq(d))
      } else {
        loop(i + 1, hashSet ++ Seq(d))
      }
    }

    loop(startNonce)
  }

}

object SNISPGenerator {
  def apply(powScheme: AutolykosPowScheme): SNISPGenerator = new SNISPGenerator(powScheme)

  val mu: Int = 20
}
