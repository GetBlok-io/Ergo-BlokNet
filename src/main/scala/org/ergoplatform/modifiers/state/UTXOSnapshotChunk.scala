package org.ergoplatform.modifiers.state

import io.circe.Json
import org.ergoplatform.modifiers.mempool.proposition.AnyoneCanSpendNoncedBox
import org.ergoplatform.settings.Algos
import scorex.core.NodeViewModifier.{ModifierId, ModifierTypeId}
import scorex.core.serialization.Serializer
import UTXOSnapshotChunk.StateElement

case class UTXOSnapshotChunk(stateElements: Seq[StateElement], index: Short) extends StateModifier {
  override val modifierTypeId: ModifierTypeId = UTXOSnapshotChunk.ModifierTypeId

  override lazy val id: ModifierId = ???

  override type M = UTXOSnapshotChunk

  override lazy val serializer: Serializer[UTXOSnapshotChunk] = ???

  override lazy val json: Json = ???

  lazy val rootHash: Array[Byte] = Algos.merkleTreeRoot(stateElements.map(_.bytes))
}

object UTXOSnapshotChunk {
  type StateElement = AnyoneCanSpendNoncedBox

  val ModifierTypeId: Byte = 107: Byte
}
