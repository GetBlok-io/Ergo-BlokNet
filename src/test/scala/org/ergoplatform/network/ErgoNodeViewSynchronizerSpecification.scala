package org.ergoplatform.network

import akka.actor.{ActorRef, ActorSystem, Cancellable, Props}
import akka.testkit.TestProbe
import org.ergoplatform.modifiers.ErgoFullBlock
import org.ergoplatform.modifiers.history.header.{Header, HeaderSerializer}
import org.ergoplatform.network.ErgoNodeViewSynchronizer.ReceivableMessages._
import org.ergoplatform.nodeView.ErgoNodeViewHolder
import org.ergoplatform.nodeView.history.ErgoHistory
import org.ergoplatform.nodeView.history.{ErgoHistoryReader, ErgoSyncInfoMessageSpec, ErgoSyncInfoV2}
import org.ergoplatform.nodeView.mempool.ErgoMemPool
import org.ergoplatform.nodeView.state.wrapped.WrappedUtxoState
import org.ergoplatform.nodeView.state.{StateType, UtxoState}
import org.ergoplatform.sanity.ErgoSanity._
import org.ergoplatform.settings.ErgoSettings
import org.ergoplatform.utils.HistoryTestHelpers
import org.scalacheck.Gen
import org.scalatest.concurrent.Eventually
import org.scalatest.matchers.should.Matchers
import scorex.core.PersistentNodeViewModifier
import scorex.core.network.ModifiersStatus.{Received, Unknown}
import scorex.core.network.NetworkController.ReceivableMessages.SendToNetwork
import scorex.core.network.message._
import scorex.core.network.peer.PeerInfo
import scorex.core.network.{ConnectedPeer, DeliveryTracker}
import scorex.core.serialization.ScorexSerializer
import scorex.core.utils.NetworkTimeProvider
import scorex.testkit.utils.AkkaFixture

import scala.concurrent.duration.{Duration, _}
import scala.concurrent.{Await, ExecutionContext, ExecutionContextExecutor}
import scala.language.postfixOps

class ErgoNodeViewSynchronizerSpecification extends HistoryTestHelpers with Matchers with Eventually {

  // ToDo: factor this out of here and NVHTests?
  private def withFixture(testCode: SynchronizerFixture => Any): Unit = {
    val fixture = new SynchronizerFixture
    try {
      testCode(fixture)
    }
    finally {
      Await.result(fixture.system.terminate(), Duration.Inf)
    }
  }

  private def withFixture2(testCode: Synchronizer2Fixture => Any): Unit = {
    val fixture = new Synchronizer2Fixture
    try {
      testCode(fixture)
    }
    finally {
      Await.result(fixture.system.terminate(), Duration.Inf)
    }
  }

  class NodeViewHolderMock extends ErgoNodeViewHolder[UtxoState](settings, timeProvider)

  class SynchronizerMock(networkControllerRef: ActorRef,
                         viewHolderRef: ActorRef,
                         syncInfoSpec: ErgoSyncInfoMessageSpec.type,
                         settings: ErgoSettings,
                         timeProvider: NetworkTimeProvider,
                         syncTracker: ErgoSyncTracker,
                         deliveryTracker: DeliveryTracker)
                        (implicit ec: ExecutionContext) extends ErgoNodeViewSynchronizer(
    networkControllerRef,
    viewHolderRef,
    syncInfoSpec,
    settings,
    timeProvider,
    syncTracker,
    deliveryTracker)(ec) {

    override protected def broadcastInvForNewModifier(mod: PersistentNodeViewModifier): Unit = {
      mod match {
        case fb: ErgoFullBlock if fb.header.isNew(timeProvider, 1.hour) =>
          fb.toSeq.foreach(s => broadcastModifierInv(s))
        case h: Header if h.isNew(timeProvider, 1.hour) =>
          broadcastModifierInv(h)
        case _ =>
      }
    }
  }

  override implicit val patienceConfig: PatienceConfig = PatienceConfig(2.seconds, 100.millis)
  val history = generateHistory(verifyTransactions = true, StateType.Utxo, PoPoWBootstrap = false, blocksToKeep = -1)
  val chain = genHeaderChain(2000, history, diffBitsOpt = None, useRealTs = false)
  val localChain = chain.take(1000)
  val altchain = genHeaderChain(1000, history, diffBitsOpt = None, useRealTs = false)

  val forkedChain = {
    val c = localChain.take(1000 - 512)
    c ++ genHeaderChain(512, Some(c.last), diffBitsOpt = None, useRealTs = false).tail
  }
  val forkedHeight = forkedChain.last.height

  val localHistoryGen: Gen[HT] = {
    require(history.isEmpty)
    applyHeaderChain(history, localChain)
  }

  val localStateGen: Gen[WrappedUtxoState] =
    boxesHolderGen.map(WrappedUtxoState(_, createTempDir, None, parameters, settings))

  def semanticallyValidModifier(state: UTXO_ST): PM = {
    statefulyValidFullBlock(state.asInstanceOf[WrappedUtxoState])
  }

  def semanticallyInvalidModifier(state: UTXO_ST): PM = invalidErgoFullBlockGen.sample.get

  def totallyValidModifier(history: HT, state: UTXO_ST): PM = {
    val parentOpt = history.bestFullBlockOpt
    validFullBlock(parentOpt, state.asInstanceOf[WrappedUtxoState]).header
  }

  def totallyValidModifiers(history: HT, state: UTXO_ST, count: Int): Seq[PM] = {
    require(count >= 1)
    val headerOpt = history.bestFullBlockOpt
    (0 until count).foldLeft((headerOpt, Seq.empty[PM])) { case (acc, _) =>
      val pm = validFullBlock(headerOpt, state.asInstanceOf[WrappedUtxoState])
      (Some(pm), acc._2 :+ pm)
    }._2.map(_.asInstanceOf[ErgoFullBlock].header)
  }

  def nodeViewSynchronizer(implicit system: ActorSystem):
  (ActorRef, SI, PM, TX, ConnectedPeer, TestProbe, TestProbe, TestProbe, ScorexSerializer[PM], DeliveryTracker) = {
    @SuppressWarnings(Array("org.wartremover.warts.OptionPartial"))
    val h = localHistoryGen.sample.get
    @SuppressWarnings(Array("org.wartremover.warts.OptionPartial"))
    val s = localStateGen.sample.get
    val settings = ErgoSettings.read()
    val pool = ErgoMemPool.empty(settings)
    implicit val ec: ExecutionContextExecutor = system.dispatcher
    val tp = new NetworkTimeProvider(settings.scorexSettings.ntp)
    val ncProbe = TestProbe("NetworkControllerProbe")
    val pchProbe = TestProbe("PeerHandlerProbe")
    val eventListener = TestProbe("EventListener")
    val syncTracker = ErgoSyncTracker(system, settings.scorexSettings.network, timeProvider)
    val deliveryTracker: DeliveryTracker = DeliveryTracker.empty(settings)

    val nodeViewHolderMockRef = system.actorOf(Props(new NodeViewHolderMock))

    val synchronizerMockRef = system.actorOf(Props(
      new SynchronizerMock(
        ncProbe.ref,
        nodeViewHolderMockRef,
        ErgoSyncInfoMessageSpec,
        settings,
        tp,
        syncTracker,
        deliveryTracker)
    ))
    val m = totallyValidModifier(h, s)
    @SuppressWarnings(Array("org.wartremover.warts.OptionPartial"))
    val tx = validErgoTransactionGenTemplate(0, 0).sample.get._2

    val peerInfo = PeerInfo(defaultPeerSpec, timeProvider.time())
    @SuppressWarnings(Array("org.wartremover.warts.OptionPartial"))
    val p: ConnectedPeer = ConnectedPeer(
      connectionIdGen.sample.get,
      pchProbe.ref,
      lastMessage = 0,
      Some(peerInfo)
    )
    synchronizerMockRef ! ChangedHistory(history)
    synchronizerMockRef ! ChangedMempool(pool)
    val serializer: ScorexSerializer[PM] = HeaderSerializer.asInstanceOf[ScorexSerializer[PM]]
    (synchronizerMockRef, h.syncInfoV1, m, tx, p, pchProbe, ncProbe, eventListener, serializer, deliveryTracker)
  }

  class SynchronizerFixture extends AkkaFixture {
    @SuppressWarnings(Array("org.wartremover.warts.PublicInference"))
    val (node, syncInfo, mod, tx, peer, pchProbe, ncProbe, eventListener, modSerializer, deliveryTracker) = nodeViewSynchronizer
  }

  class Synchronizer2Fixture extends AkkaFixture {
      implicit val ec: ExecutionContextExecutor = system.dispatcher
      val ncProbe = TestProbe("NetworkControllerProbe")
      val pchProbe = TestProbe("PeerHandlerProbe")
      val syncTracker = ErgoSyncTracker(system, settings.scorexSettings.network, timeProvider)
      val deliveryTracker: DeliveryTracker = DeliveryTracker.empty(settings)

      val nodeViewHolderMockRef = system.actorOf(Props(new NodeViewHolderMock))

      val synchronizerMockRef = system.actorOf(Props(
        new SynchronizerMock(
          ncProbe.ref,
          nodeViewHolderMockRef,
          ErgoSyncInfoMessageSpec,
          settings,
          timeProvider,
          syncTracker,
          deliveryTracker)
      ))

      val peerInfo = PeerInfo(defaultPeerSpec, timeProvider.time())
      @SuppressWarnings(Array("org.wartremover.warts.OptionPartial"))
      val peer: ConnectedPeer = ConnectedPeer(
        connectionIdGen.sample.get,
        pchProbe.ref,
        lastMessage = 0,
        Some(peerInfo)
      )
  }

  property("NodeViewSynchronizer: Message: SyncInfoSpec V2 - younger peer") {
    withFixture { ctx =>
      import ctx._

      val emptySync = ErgoSyncInfoV2(Seq.empty)

      // Neighbour is sending
      val msgBytes = ErgoSyncInfoMessageSpec.toBytes(emptySync)

      // we check that in case of neighbour with empty history (it has no any blocks),
      // inv message with our block ids will be sent
      node ! Message(ErgoSyncInfoMessageSpec, Left(msgBytes), Some(peer))
      ncProbe.fishForMessage(3 seconds) { case m =>
        m match {
          case stn: SendToNetwork =>
            val msg = stn.message
            msg.spec.messageCode == InvSpec.MessageCode &&
            msg.data.get.asInstanceOf[InvData].ids.head == chain.head.id
          case _ => false
        }
      }
    }
  }

  property("NodeViewSynchronizer: receiving valid header") {
    withFixture { ctx =>
      import ctx._
      deliveryTracker.reset()
      deliveryTracker.setRequested(Seq(chain.take(1001).last.id), Header.modifierTypeId, Some(peer))(_ => Cancellable.alreadyCancelled)
      val olderChain = chain.take(1001)
      val modData = ModifiersData(Header.modifierTypeId, Map(olderChain.last.id -> olderChain.last.bytes))
      val modSpec = new ModifiersSpec(100)
      node ! Message(modSpec, Left(modSpec.toBytes(modData)), Some(peer))
      // desired state of submitting valid headers is Received
      eventually {
        deliveryTracker.status(olderChain.last.id, Header.modifierTypeId, Seq.empty) shouldBe Received
      }
    }
  }

  property("NodeViewSynchronizer: receiving out-of-order header should request it again") {
    withFixture2 { ctx =>
      import ctx._

      implicit val patienceConfig: PatienceConfig = PatienceConfig(5.seconds, 100.millis)

      def sendHeader(synchronizerRef: ActorRef,  header: Header): Unit = {
        deliveryTracker.setRequested(Seq(header.id), Header.modifierTypeId, Some(peer))(_ => Cancellable.alreadyCancelled)
        val modData = ModifiersData(Header.modifierTypeId, Map(header.id -> header.bytes))
        val modSpec = new ModifiersSpec(100)
        synchronizerRef ! Message(modSpec, Left(modSpec.toBytes(modData)), Some(peer))
      }

      deliveryTracker.reset()

      // we generate fork of two headers, starting from the parent of the best header
      // so the depth of the rollback is 1, and the fork bypasses the best chain by 1 header
      val hhistory = ErgoHistory.readOrGenerate(settings, timeProvider)
      val parent = hhistory.lastHeaders(2).head
      val smallFork = genHeaderChain(_.size > 2, Some(parent), hhistory.difficultyCalculator, None, false)
      val secondForkHeader = smallFork.last

      sendHeader(synchronizerMockRef, secondForkHeader)
      // we submit header at best height + 1, but with parent not known, the status should  be unknown,
      // so after some time the header could be downloaded again (when the parent may be known)
      eventually {
        deliveryTracker.status(secondForkHeader.id, Header.modifierTypeId, Seq.empty) shouldBe Unknown
      }
    }
  }

  property("NodeViewSynchronizer: Message: SyncInfoSpec V2 - older peer") {
    withFixture { ctx =>
      import ctx._

      val sync = ErgoSyncInfoV2(Seq(chain.last))

      // Neighbour is sending
      val msgBytes = ErgoSyncInfoMessageSpec.toBytes(sync)

      // we check that in case of neighbour with older history (it has more blocks),
      // sync message will be sent by our node (to get invs from the neighbour),
      // sync message will consist of 4 headers
      node ! Message(ErgoSyncInfoMessageSpec, Left(msgBytes), Some(peer))
      ncProbe.fishForMessage(3 seconds) { case m =>
        m match {
          case stn: SendToNetwork =>
            val msg = stn.message
            val headers = msg.data.get.asInstanceOf[ErgoSyncInfoV2].lastHeaders
            msg.spec.messageCode == ErgoSyncInfoMessageSpec.messageCode && headers.length == 4
          case _ => false
        }
      }
    }
  }

  property("NodeViewSynchronizer: Message: SyncInfoSpec V2 - unknown peer") {
    withFixture { ctx =>
      import ctx._

      val sync = ErgoSyncInfoV2(Seq(altchain.last))

      // Neighbour is sending
      val msgBytes = ErgoSyncInfoMessageSpec.toBytes(sync)

      // we check that in case of neighbour with older history (it has more blocks),
      // sync message will be sent by our node (to get invs from the neighbour),
      // sync message will consist of 4 headers
      node ! Message(ErgoSyncInfoMessageSpec, Left(msgBytes), Some(peer))
      ncProbe.fishForMessage(3 seconds) { case m =>
        m match {
          case stn: SendToNetwork =>
            val msg = stn.message
            val headers = msg.data.get.asInstanceOf[ErgoSyncInfoV2].lastHeaders
            msg.spec.messageCode == ErgoSyncInfoMessageSpec.messageCode && headers.length == 4
          case _ => false
        }
      }
    }
  }

  property("NodeViewSynchronizer: Message: SyncInfoSpec V2 - forked peer") {
    withFixture { ctx =>
      import ctx._

      val sync = ErgoSyncInfoV2(ErgoHistoryReader.FullV2SyncOffsets.map(offset => forkedChain.apply(forkedHeight - offset - 1)))

      // Neighbour is sending
      val msgBytes = ErgoSyncInfoMessageSpec.toBytes(sync)

      // we check that in case of neighbour with older history (it has more blocks),
      // invs (extension for the forked peer) will be sent to the peer
      node ! Message(ErgoSyncInfoMessageSpec, Left(msgBytes), Some(peer))
      ncProbe.fishForMessage(3 seconds) { case m =>
        m match {
          case stn: SendToNetwork =>
            val msg = stn.message
            msg.spec.messageCode == InvSpec.MessageCode
          case _ => false
        }
      }
    }
  }

}
