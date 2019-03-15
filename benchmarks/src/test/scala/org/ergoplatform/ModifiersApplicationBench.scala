package org.ergoplatform

import org.ergoplatform.modifiers.ErgoPersistentModifier
import org.ergoplatform.modifiers.history.{BlockTransactions, Extension, Header}
import org.ergoplatform.nodeView.{ErgoModifiersCache, NVBenchmark}
import org.ergoplatform.nodeView.history.ErgoHistory
import org.ergoplatform.nodeView.state.StateType
import org.ergoplatform.utils.HistoryTestHelpers

import scala.annotation.tailrec

object ModifiersApplicationBench extends HistoryTestHelpers with NVBenchmark with App {

  override def main(args: Array[String]): Unit = {

    val cache = new ErgoModifiersCache(maxSize = 1024)

    val headers: Seq[Header] = readHeaders
    val payloads: Seq[BlockTransactions] = readPayloads
    val extensions: Seq[Extension] = readExtensions

    def bench(benchCase: String)
             (applicator: (Seq[ErgoPersistentModifier], ErgoHistory) => Any,
              mods: Seq[ErgoPersistentModifier]): String = {
      val preparedHistory = applyModifiers(headers.take(mods.size / 2), unlockedHistory())._1
      val et = time(applicator(mods, preparedHistory))
      assert(preparedHistory.fullBlockHeight == mods.size / 2)
      s"Performance of `$benchCase`: $et ms"
    }

    def applyModifiersWithCache(mods: Seq[ErgoPersistentModifier], his: ErgoHistory): (ErgoHistory, Int) = {
      mods.foreach(m => cache.put(m.id, m))
      @tailrec def applyLoop(applied: Seq[ErgoPersistentModifier]): Seq[ErgoPersistentModifier] = {
        cache.popCandidate(his) match {
          case Some(mod) =>
            his.append(mod).get
            applyLoop(mod +: applied)
          case None =>
            applied
        }
      }

      val appliedModsQty = applyLoop(Seq()).size
      his -> appliedModsQty
    }

    def applyModifiers(mods: Seq[ErgoPersistentModifier], his: ErgoHistory): (ErgoHistory, Int) = {
      @tailrec def applyLoop(rem: Seq[ErgoPersistentModifier],
                             applied: Seq[ErgoPersistentModifier]): Seq[ErgoPersistentModifier] = {
        rem match {
          case m :: tail =>
            his.applicableTry(m)
            his.append(m)
            applyLoop(tail, m +: applied)
          case Nil =>
            applied
        }
      }

      val appliedModsQty = applyLoop(mods, Seq()).size
      his -> appliedModsQty
    }

    val modifiersDirectOrd = payloads ++ extensions
    val modifiersReversedOrd = modifiersDirectOrd.reverse
    val report0 = bench("Modifiers application in direct order")(applyModifiers, modifiersDirectOrd)
    val report1 = bench("Modifiers application in reversed order")(applyModifiers, modifiersReversedOrd)
    val report2 = bench("Modifiers application in direct order (cache)")(applyModifiersWithCache, modifiersDirectOrd)
    val report3 = bench("Modifiers application in reversed order (cache)")(applyModifiersWithCache, modifiersReversedOrd)

    println(report0)
    println(report1)
    println(report2)
    println(report3)

    System.exit(0)
  }

  def history(): ErgoHistory = generateHistory(verifyTransactions = true, StateType.Utxo,
    PoPoWBootstrap = false, blocksToKeep = -1)

  def unlockedHistory(): ErgoHistory = {
    val h = history()
    HistoryTestHelpers.allowToApplyOldBlocks(h)
    h
  }

}
