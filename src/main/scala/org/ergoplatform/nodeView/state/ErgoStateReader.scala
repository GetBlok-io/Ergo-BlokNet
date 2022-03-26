package org.ergoplatform.nodeView.state

import org.ergoplatform.ErgoBox
import org.ergoplatform.settings.{Algos, Parameters, VotingSettings}
import scorex.core.{NodeViewComponent, VersionTag}
import scorex.crypto.authds.ADDigest
import scorex.crypto.hash.Digest32
import scorex.db.LDBVersionedStore
import scorex.util.ScorexLogging

trait ErgoStateReader extends NodeViewComponent with ScorexLogging {

  def rootHash: ADDigest
  def parameters: Parameters
  val store: LDBVersionedStore
  val constants: StateConstants

  private lazy val chainSettings = constants.settings.chainSettings

  protected lazy val votingSettings: VotingSettings = chainSettings.voting

  def stateContext: ErgoStateContext = ErgoStateReader.storageStateContext(store, constants, parameters)

  def genesisBoxes: Seq[ErgoBox] = ErgoState.genesisBoxes(chainSettings)

  //must be ID of last applied modifier
  def version: VersionTag

  def closeStorage(): Unit = {
    log.warn("Closing state's store.")
    store.close()
  }

}

object ErgoStateReader {

  val ContextKey: Digest32 = Algos.hash("current state context")

  def storageStateContext(store: LDBVersionedStore, constants: StateConstants, parameters: Parameters): ErgoStateContext = {
    store.get(ErgoStateReader.ContextKey)
      .flatMap(b => ErgoStateContextSerializer(constants.settings).parseBytesTry(b).toOption)
      .getOrElse(ErgoStateContext.empty(constants, parameters))
  }

}
