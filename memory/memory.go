package memory

import (
	"context"
	"encoding/binary"
	"github.com/sergeyzav/memprocfs"
	"math"
	"sync"
	"time"
)

type unit struct {
	address uint64
	size    uint32
	buffer  []byte
	resChan chan<- []byte
	timer   *time.Timer
}

type Memory struct {
	locker      sync.Mutex
	scatterTask *memprocfs.ScatterTask
	units       []*unit
	limits      int
	ops         int
}

func NewMemory(scatterTask *memprocfs.ScatterTask, limits int) *Memory {
	return &Memory{
		scatterTask: scatterTask,
		limits:      limits,
	}
}

func (m *Memory) Read(ctx context.Context, address uint64, size uint32, tte time.Duration) (<-chan []byte, error) {
	m.locker.Lock()
	defer m.locker.Unlock()

	result := make(chan []byte, 1)

	task := &unit{
		address: address,
		size:    size,
		resChan: result,
		buffer:  make([]byte, size),
	}

	err := m.scatterTask.PrepareRead(ctx, address, task.buffer)

	if err != nil {
		return nil, err
	}

	task.timer = time.AfterFunc(tte, func() {
		m.ReadExecute(ctx)
	})

	m.units = append(m.units, task)
	m.ops++

	if m.ops > m.limits {
		m.ReadExecute(ctx)
	}

	return result, nil
}

func (m *Memory) ReadUint64(ctx context.Context, address uint64, tte time.Duration) (<-chan uint64, error) {
	res := make(chan uint64, 1)

	bytesResult, err := m.Read(ctx, address, 8, tte)

	if err != nil {
		return nil, err
	}

	go func() {
		defer close(res)
		for bts := range bytesResult {
			res <- binary.LittleEndian.Uint64(bts)
		}
	}()

	return res, nil
}

func (m *Memory) ReadUint32(ctx context.Context, address uint64, tte time.Duration) (<-chan uint32, error) {
	res := make(chan uint32, 1)

	bytesResult, err := m.Read(ctx, address, 4, tte)

	if err != nil {
		return nil, err
	}

	go func() {
		defer close(res)
		for bts := range bytesResult {
			res <- binary.LittleEndian.Uint32(bts)
		}
	}()

	return res, nil
}

func (m *Memory) ReadInt32(ctx context.Context, address uint64, tte time.Duration) (<-chan int32, error) {
	res := make(chan int32, 1)

	bytesResult, err := m.Read(ctx, address, 4, tte)

	if err != nil {
		return nil, err
	}

	go func() {
		defer close(res)
		for bts := range bytesResult {
			res <- int32(binary.LittleEndian.Uint32(bts))
		}
	}()

	return res, nil
}

func (m *Memory) ReadInt64(ctx context.Context, address uint64, tte time.Duration) (<-chan int64, error) {
	res := make(chan int64, 1)

	bytesResult, err := m.Read(ctx, address, 8, tte)

	if err != nil {
		return nil, err
	}

	go func() {
		defer close(res)
		for bts := range bytesResult {
			res <- int64(binary.LittleEndian.Uint64(bts))
		}
	}()

	return res, nil
}

func (m *Memory) ReadUint16(ctx context.Context, address uint64, tte time.Duration) (<-chan uint16, error) {
	res := make(chan uint16, 1)

	bytesResult, err := m.Read(ctx, address, 2, tte)

	if err != nil {
		return nil, err
	}

	go func() {
		defer close(res)
		for bts := range bytesResult {
			res <- binary.LittleEndian.Uint16(bts)
		}
	}()

	return res, nil
}

func (m *Memory) ReadUint8(ctx context.Context, address uint64, tte time.Duration) (<-chan uint8, error) {
	res := make(chan uint8, 1)

	bytesResult, err := m.Read(ctx, address, 1, tte)

	if err != nil {
		return nil, err
	}

	go func() {
		defer close(res)
		for bts := range bytesResult {
			res <- bts[0]
		}
	}()

	return res, nil
}

func (m *Memory) ReadBool(ctx context.Context, address uint64, tte time.Duration) (<-chan bool, error) {
	res := make(chan bool, 1)

	bytesResult, err := m.Read(ctx, address, 1, tte)

	if err != nil {
		return nil, err
	}

	go func() {
		defer close(res)
		for bts := range bytesResult {
			res <- bts[0] > 0
		}
	}()

	return res, nil
}

func (m *Memory) ReadFloat32(ctx context.Context, address uint64, tte time.Duration) (<-chan float32, error) {
	res := make(chan float32, 1)

	bytesResult, err := m.Read(ctx, address, 4, tte)

	if err != nil {
		return nil, err
	}

	go func() {
		defer close(res)
		for bts := range bytesResult {
			u32 := binary.LittleEndian.Uint32(bts)
			res <- math.Float32frombits(u32)
		}
	}()

	return res, nil
}

func (m *Memory) ReadFloat64(ctx context.Context, address uint64, tte time.Duration) (<-chan float64, error) {
	res := make(chan float64, 1)

	bytesResult, err := m.Read(ctx, address, 8, tte)

	if err != nil {
		return nil, err
	}

	go func() {
		defer close(res)
		for bts := range bytesResult {
			u64 := binary.LittleEndian.Uint64(bts)
			res <- math.Float64frombits(u64)
		}
	}()

	return res, nil
}

func (m *Memory) ReadExecute(ctx context.Context) error {
	m.locker.Lock()
	defer m.locker.Unlock()

	err := m.scatterTask.Execute(ctx)

	if err != nil {
		return err
	}

	defer m.scatterTask.Clear(ctx)

	for _, u := range m.units {
		u.timer.Stop()
		u.resChan <- u.buffer
		close(u.resChan)
	}

	m.units = []*unit{}
	m.ops = 0
	return nil
}

func (m *Memory) Close(ctx context.Context) error {
	return m.scatterTask.Close(ctx)
}

func ReadStruct[T any](ctx context.Context, m *Memory, address uint64, tte time.Duration) (<-chan T, error) {
	res := make(chan T, 1)

	var t T
	size := binary.Size(t)
	bytesResult, err := m.Read(ctx, address, uint32(size), tte)

	if err != nil {
		return nil, err
	}

	go func() {
		defer close(res)
		for bts := range bytesResult {
			var rt T
			binary.Decode(bts, binary.LittleEndian, &rt)
			res <- rt
		}
	}()

	return res, nil
}
