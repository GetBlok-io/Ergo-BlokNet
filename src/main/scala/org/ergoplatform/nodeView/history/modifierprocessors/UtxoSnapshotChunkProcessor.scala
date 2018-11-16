package org.ergoplatform.nodeView.history.modifierprocessors

import com.google.common.primitives.Ints
import io.iohk.iodb.ByteArrayWrapper
import org.ergoplatform.modifiers.{ErgoFullBlock, ErgoPersistentModifier}
import org.ergoplatform.modifiers.history.Header
import org.ergoplatform.modifiers.state.{UtxoSnapshot, UtxoSnapshotChunk, UtxoSnapshotManifest}
import org.ergoplatform.nodeView.history.storage.HistoryStorage
import org.ergoplatform.settings.{Algos, Constants}
import scorex.core.ModifierTypeId
import scorex.core.consensus.History.ProgressInfo
import scorex.core.utils.ScorexEncoding
import scorex.util.{ModifierId, ScorexLogging}

import scala.util.{Failure, Success, Try}

trait UtxoSnapshotChunkProcessor extends ScorexLogging with ScorexEncoding {

  protected val historyStorage: HistoryStorage

  private val emptyProgressInfo = ProgressInfo[ErgoPersistentModifier](None, Seq.empty, Seq.empty, Seq.empty)

  protected val LastSnapshotAppliedHeightKey: ByteArrayWrapper =
    ByteArrayWrapper(Array.fill(Constants.HashLength)(UtxoSnapshot.modifierTypeId))

  protected def lastSnapshotAppliedHeight: Option[Int] = historyStorage.getIndex(LastSnapshotAppliedHeightKey)
    .map(w => Ints.fromByteArray(w.data))

  protected def toDownload(header: Header): Seq[(ModifierTypeId, ModifierId)]

  def process(m: UtxoSnapshotChunk): ProgressInfo[ErgoPersistentModifier] = {
    historyStorage.modifierById(m.manifestId) match {
      case Some(manifest: UtxoSnapshotManifest) =>
        val otherChunks = manifest.chunkRoots
          .map(r => historyStorage.modifierById(UtxoSnapshot.rootDigestToId(r)))
          .collect { case Some(chunk: UtxoSnapshotChunk) => chunk }
        lazy val lastHeaders = takeLastHeaders(manifest.blockId, Constants.LastHeadersInContext)
        if (otherChunks.lengthCompare(manifest.size - 1) == 0 &&
          lastHeaders.lengthCompare(Constants.LastHeadersInContext) == 0) {
          // Time to apply snapshot
          val snapshot = UtxoSnapshot(manifest, otherChunks :+ m, lastHeaders)
          val snapshotHeight = lastHeaders.head.height
          val indexesToInsert = Seq(LastSnapshotAppliedHeightKey -> ByteArrayWrapper(Ints.toByteArray(snapshotHeight)))
          historyStorage.insert(Algos.idToBAW(m.id), indexesToInsert, Seq.empty)
          ProgressInfo(None, Seq.empty, Seq(snapshot), toDownload(lastHeaders.head))
        } else {
          historyStorage.insertObjects(Seq(m))
          emptyProgressInfo
        }
      case _ =>
        emptyProgressInfo
    }
  }

  def validate(m: UtxoSnapshotChunk): Try[Unit] = if (historyStorage.contains(m.id)) {
    Failure(new Exception(s"UtxoSnapshotChunk with id ${m.encodedId} is already in history"))
  } else {
    Success(Unit)
  }

  private def takeLastHeaders(lastHeaderId: ModifierId, qty: Int): Seq[Header] = {
    (0 to qty).foldLeft(Seq.empty[Header]) { case (acc, _) =>
      historyStorage.modifierById(acc.headOption.map(_.parentId).getOrElse(lastHeaderId)) match {
        case Some(h: Header) =>
          acc :+ h
        case _ =>
          acc
      }
    }
  }

}
