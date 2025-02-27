package org.ergoplatform.nodeView.history.storage.modifierprocessors.popow

import org.ergoplatform.modifiers.BlockSection
import org.ergoplatform.modifiers.history.{HeaderChain, NipopowProofModifier}
import org.ergoplatform.nodeView.history.storage.modifierprocessors.HeadersProcessor
import scorex.core.consensus.ProgressInfo
import scorex.util.ScorexLogging

import scala.util.Try

/**
  * Contains all functions required by History to process PoPowProofModifier and generate them.
  */
trait PoPoWProofsProcessor extends HeadersProcessor with ScorexLogging {

  def validate(m: NipopowProofModifier): Try[Unit]

  def process(m: NipopowProofModifier): Try[ProgressInfo[BlockSection]]

  def lastHeaders(count: Int, offset: Int = 0): HeaderChain
}
