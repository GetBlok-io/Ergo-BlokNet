package org.ergoplatform.nodeView.history.storage.modifierprocessors

import org.ergoplatform.modifiers.BlockSection
import org.ergoplatform.modifiers.state.UTXOSnapshotChunk
import org.ergoplatform.nodeView.history.storage.HistoryStorage
import scorex.core.consensus.ProgressInfo
import scorex.core.utils.ScorexEncoding
import scorex.util.ScorexLogging

import scala.util.{Failure, Success, Try}

/**
  * Contains all functions required by History to process UTXOSnapshotChunk
  */
trait UTXOSnapshotChunkProcessor extends ScorexLogging with ScorexEncoding {

  protected val historyStorage: HistoryStorage

  def process(m: UTXOSnapshotChunk): Try[ProgressInfo[BlockSection]] = ???
/*
    {
      //TODO
      val toInsert = ???
      historyStorage.insert(Seq.empty, toInsert).map { _ =>
        ProgressInfo(None, Seq.empty, Seq(m), Seq.empty)
      }
    }
*/

  def validate(m: UTXOSnapshotChunk): Try[Unit] = if (historyStorage.contains(m.id)) {
    Failure(new Error(s"UTXOSnapshotChunk with id ${m.encodedId} is already in history"))
  } else {
    Success(Unit)
  }

}
