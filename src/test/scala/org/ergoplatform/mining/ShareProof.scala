package org.ergoplatform.mining

// Share Proof class holding information about proof
// In reality, proof would likely include headers as well
case class ShareProof(proof: Seq[BigInt], tau: BigInt, i: Int, N: Long){
  def isValid: Boolean = proof.size == i && proof.forall(_ < (tau * i) / N)
}
