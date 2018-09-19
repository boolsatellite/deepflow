package capture

import (
	"runtime"
	"sync"
	"time"

	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/dedup"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
)

type Timestamp = time.Duration
type RawPacket = []byte
type PacketSize = int

type PacketHandler interface {
	Handle(Timestamp, RawPacket, PacketSize)
}

type MetaPacketBlock = [1024]datatype.MetaPacket

type DataHandler struct {
	sync.Pool

	block       *MetaPacketBlock
	blockCursor int

	ip    datatype.IPv4Int
	queue queue.MultiQueueWriter

	dedupTable *dedup.DedupTable
}

func (h *DataHandler) preAlloc() *datatype.MetaPacket {
	metaPacket := &h.block[h.blockCursor]
	metaPacket.Exporter = h.ip
	return metaPacket
}

func (h *DataHandler) confirmAlloc() {
	h.blockCursor++
	if h.blockCursor >= len(*h.block) {
		h.block = h.Get().(*MetaPacketBlock)
		h.blockCursor = 0
	}
}

func (h *DataHandler) Handle(timestamp Timestamp, packet RawPacket, size PacketSize) {
	metaPacket := h.preAlloc()
	metaPacket.InPort = uint32(datatype.PACKET_SOURCE_ISP)
	metaPacket.Timestamp = timestamp
	metaPacket.PacketLen = uint16(size)
	if !metaPacket.Parse(packet) {
		return
	}
	h.confirmAlloc()
	h.queue.Put(queue.HashKey(metaPacket.GenerateHash()), metaPacket)
}

func (h *DataHandler) Init(interfaceName string) *DataHandler {
	h.dedupTable = dedup.NewDedupTable(interfaceName)
	gc := func(b *MetaPacketBlock) {
		*b = MetaPacketBlock{} // 重新初始化，避免无效的数据或不可预期的引用
		h.Put(b)
	}
	h.Pool.New = func() interface{} {
		block := new(MetaPacketBlock)
		runtime.SetFinalizer(block, gc)
		return block
	}
	h.block = new(MetaPacketBlock)
	return h
}

type TapHandler DataHandler

func (h *TapHandler) Handle(timestamp Timestamp, packet RawPacket, size PacketSize) {
	metaPacket := (*DataHandler)(h).preAlloc()
	metaPacket.InPort = uint32(datatype.PACKET_SOURCE_TOR)
	metaPacket.Timestamp = timestamp
	metaPacket.PacketLen = uint16(size)
	tunnel := datatype.TunnelInfo{}
	if offset := tunnel.Decapsulate(packet); offset > 0 {
		packet = packet[offset:]
		metaPacket.Tunnel = &tunnel
	}
	if h.dedupTable.IsDuplicate(packet, timestamp) {
		return
	}
	if !metaPacket.Parse(packet) {
		return
	}
	(*DataHandler)(h).confirmAlloc()
	h.queue.Put(queue.HashKey(metaPacket.GenerateHash()), metaPacket)
}
