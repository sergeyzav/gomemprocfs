package memory

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/sergeyzav/memprocfs"
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

func readAndConvert[T any](m *Memory, ctx context.Context, address uint64, size uint32, tte time.Duration, convert func([]byte) T) (<-chan T, error) {
	res := make(chan T, 1)

	bytesResult, err := m.Read(ctx, address, size, tte)
	if err != nil {
		return nil, err
	}

	go func() {
		defer close(res)
		for bts := range bytesResult {
			res <- convert(bts)
		}
	}()

	return res, nil
}

func (m *Memory) ReadUint64(ctx context.Context, address uint64, tte time.Duration) (<-chan uint64, error) {
	return readAndConvert(m, ctx, address, 8, tte, binary.LittleEndian.Uint64)
}

func (m *Memory) ReadUint32(ctx context.Context, address uint64, tte time.Duration) (<-chan uint32, error) {
	return readAndConvert(m, ctx, address, 4, tte, binary.LittleEndian.Uint32)
}

func (m *Memory) ReadInt32(ctx context.Context, address uint64, tte time.Duration) (<-chan int32, error) {
	return readAndConvert(m, ctx, address, 4, tte, func(b []byte) int32 { return int32(binary.LittleEndian.Uint32(b)) })
}

func (m *Memory) ReadInt64(ctx context.Context, address uint64, tte time.Duration) (<-chan int64, error) {
	return readAndConvert(m, ctx, address, 8, tte, func(b []byte) int64 { return int64(binary.LittleEndian.Uint64(b)) })
}

func (m *Memory) ReadUint16(ctx context.Context, address uint64, tte time.Duration) (<-chan uint16, error) {
	return readAndConvert(m, ctx, address, 2, tte, binary.LittleEndian.Uint16)
}

func (m *Memory) ReadUint8(ctx context.Context, address uint64, tte time.Duration) (<-chan uint8, error) {
	return readAndConvert(m, ctx, address, 1, tte, func(b []byte) uint8 { return b[0] })
}

func (m *Memory) ReadBool(ctx context.Context, address uint64, tte time.Duration) (<-chan bool, error) {
	return readAndConvert(m, ctx, address, 1, tte, func(b []byte) bool { return b[0] > 0 })
}

func (m *Memory) ReadFloat32(ctx context.Context, address uint64, tte time.Duration) (<-chan float32, error) {
	return readAndConvert(m, ctx, address, 4, tte, func(b []byte) float32 {
		return math.Float32frombits(binary.LittleEndian.Uint32(b))
	})
}

func (m *Memory) ReadFloat64(ctx context.Context, address uint64, tte time.Duration) (<-chan float64, error) {
	return readAndConvert(m, ctx, address, 8, tte, func(b []byte) float64 {
		return math.Float64frombits(binary.LittleEndian.Uint64(b))
	})
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
	if size < 0 {
		return nil, fmt.Errorf("invalid type size")
	}
	bytesResult, err := m.Read(ctx, address, uint32(size), tte)

	if err != nil {
		return nil, err
	}

	go func() {
		defer close(res)
		for bts := range bytesResult {
			var rt T
			if err := binary.Read(bytes.NewReader(bts), binary.LittleEndian, &rt); err == nil {
				res <- rt
			}
		}
	}()

	return res, nil
}
