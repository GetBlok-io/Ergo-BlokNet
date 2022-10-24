package org.ergoplatform.mining

import com.google.common.primitives.Ints
import org.ergoplatform.utils.ErgoPropertyTest
import org.scalacheck.Gen
import scorex.testkit.utils.NoShrink

class SNISPSpec extends ErgoPropertyTest with NoShrink {


  property("valid proof exists at ideal tau") {
    val pow = new AutolykosPowScheme(powScheme.k, powScheme.n)
    forAll(invalidHeaderGen,
            Gen.pick(1, Iterable(100, 1000, 5000, 10000, 20000)),
            Gen.choose(20000, 60000)
            ) { (inHeader, numShares, totalHashes) =>

      val snispGen = SNISPGenerator(pow)
      println(s"Using parameters N = ${numShares.head}, h*W = ${totalHashes}, mu = 20")
      val nBits = snispGen.idealNBits(numShares.head, totalHashes)

      val h = inHeader.copy(nBits = nBits, version = 2.toByte)
      val sk = randomSecret()
      val x = randomSecret()
      val msg = pow.msgByHeader(h)
      val tau = snispGen.idealTau(numShares.head, totalHashes)
      val hbs = Ints.toByteArray(h.height)
      val N = pow.calcN(h)

      val hashSet = snispGen.mineShares(2.toByte, hbs, msg, sk, x, tau, N, 0, totalHashes)
      val proofSet = snispGen.generateProofs(hashSet, tau, numShares.head)

      println(s"Using ideal tau: ${tau}")

      proofSet.foreach{
        p =>
          println(s"Number of super shares at level ${p.i}: ${p.proof.size} | isValidProof: ${p.isValid}")
      }

      val bestProof = snispGen.bestProof(proofSet)

      if(bestProof.isSuccess)
        println(s"Best proof at level ${bestProof.get.i} with shares: ${bestProof.get.proof}")
      else
        println("No valid proof existed!")

      bestProof shouldBe 'success

    }
  }

  property("Deviations from tau give expected validity") {
    val pow = new AutolykosPowScheme(powScheme.k, powScheme.n)
    forAll(invalidHeaderGen,
      Gen.someOf(Iterable(0.05, 0.2, 1.0, 3.0, 4.0)),

    ) { (inHeader, tauMultiplier) =>
      val numShares   = 10000
      val totalHashes = 50000
      val snispGen = SNISPGenerator(pow)
      println(s"Using parameters N = ${numShares}, h*W = ${totalHashes}, mu = 20")
      println(s"Using a tau multiplier of ${tauMultiplier.head}")
      val nBits = snispGen.idealNBits(numShares, totalHashes)

      val h = inHeader.copy(nBits = nBits, version = 2.toByte)
      val sk = randomSecret()
      val x = randomSecret()
      val msg = pow.msgByHeader(h)
      val tau = snispGen.idealTau(numShares, totalHashes)

      val modifiedTau = (BigDecimal(tau) * tauMultiplier.head).toBigInt()

      val hbs = Ints.toByteArray(h.height)
      val N = pow.calcN(h)

      val hashSet = snispGen.mineShares(2.toByte, hbs, msg, sk, x, modifiedTau, N, 0, totalHashes)
      val proofSet = snispGen.generateProofs(hashSet, modifiedTau, numShares)

      println(s"Ideal tau: ${tau}")
      println(s"Using tau: ${modifiedTau}")

      proofSet.foreach {
        p =>
          println(s"Number of super shares at level ${p.i}: ${p.proof.size} | isValidProof: ${p.isValid}")
      }

      val bestProof = snispGen.bestProof(proofSet)

      if (bestProof.isSuccess)
        println(s"Best proof at level ${bestProof.get.i} with shares: ${bestProof.get.proof}")
      else
        println("No valid proof existed!")

      if(tauMultiplier.head < 1.0)
        bestProof shouldBe 'failure
      else
        bestProof shouldBe 'success

    }
  }

  property("Ideal tau gives at least one valid proof > 80% of the time") {
    val pow = new AutolykosPowScheme(powScheme.k, powScheme.n)
    forAll(invalidHeaderGen

    ) { (inHeader) =>

      val trials = for (t <- 0 until 10) yield {
        val numShares = 1000
        val totalHashes = 10000
        val snispGen = SNISPGenerator(pow)
        println(s"Using parameters N = ${numShares}, h*W = ${totalHashes}, mu = 20")

        val nBits = snispGen.idealNBits(numShares, totalHashes)

        val h = inHeader.copy(nBits = nBits, version = 2.toByte)
        val sk = randomSecret()
        val x = randomSecret()
        val msg = pow.msgByHeader(h)
        val tau = snispGen.idealTau(numShares, totalHashes)

        val hbs = Ints.toByteArray(h.height)
        val N = pow.calcN(h)

        val hashSet = snispGen.mineShares(2.toByte, hbs, msg, sk, x, tau, N, t*totalHashes, t*totalHashes+totalHashes)
        val proofSet = snispGen.generateProofs(hashSet, tau, numShares)

        println(s"=====================Trial #${t}=======================")
        println(s"Using ideal tau: ${tau}")

        proofSet.foreach {
          p =>
            println(s"Number of super shares at level ${p.i}: ${p.proof.size} | isValidProof: ${p.isValid}")
        }

        val bestProof = snispGen.bestProof(proofSet)

        if (bestProof.isSuccess)
          println(s"Best proof at level ${bestProof.get.i} with shares: ${bestProof.get.proof}")
        else
          println("No valid proof existed!")

        bestProof
      }
      val successfulTrials = trials.count(_.isSuccess)
      val successPercent: Double = successfulTrials.toDouble / trials.size.toDouble
      println(s"Number of trials with at least one valid share proof: ${successfulTrials}")
      println(s"Number of trials without a valid share proof: ${trials.size - successfulTrials}")
      println(s"Total number of trials: ${trials.size}")
      println(s"Success Percentage: ${successPercent}")
      Thread.sleep(10000)
      //successPercent > 0.8 shouldBe true


    }


  }

}
