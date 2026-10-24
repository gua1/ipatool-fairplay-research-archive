package main

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	modelMagic   = "FPGOOR1\x00"
	modelVersion = uint32(2)
	pageSize     = uint64(0x1000)
)

type model struct {
	binaryHash [32]byte
	block      uint64
	registers  [31]uint64
	sp         uint64
	n, z, c, v bool
	pages      map[uint64][]byte
	domains    map[domainKey][256]uint64
}

type domainKey struct {
	pc       uint64
	register uint8
}

func loadModel(path string) (*model, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("Go FairPlay oracle model is not a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("Go FairPlay oracle model must be mode 0600")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	stream, err := gzip.NewReader(file)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	read := func(value any) error { return binary.Read(stream, binary.LittleEndian, value) }
	var magic [8]byte
	if _, err := io.ReadFull(stream, magic[:]); err != nil {
		return nil, err
	}
	if string(magic[:]) != modelMagic {
		return nil, fmt.Errorf("invalid Go FairPlay oracle model magic")
	}
	var version uint32
	if err := read(&version); err != nil || version != modelVersion {
		return nil, fmt.Errorf("unsupported Go FairPlay oracle model version")
	}
	result := &model{pages: make(map[uint64][]byte), domains: make(map[domainKey][256]uint64)}
	if _, err := io.ReadFull(stream, result.binaryHash[:]); err != nil {
		return nil, err
	}
	if err := read(&result.block); err != nil {
		return nil, err
	}
	for index := range result.registers {
		if err := read(&result.registers[index]); err != nil {
			return nil, err
		}
	}
	if err := read(&result.sp); err != nil {
		return nil, err
	}
	var flags [4]byte
	if _, err := io.ReadFull(stream, flags[:]); err != nil {
		return nil, err
	}
	result.n, result.z, result.c, result.v = flags[0] != 0, flags[1] != 0, flags[2] != 0, flags[3] != 0
	var pageCount uint32
	if err := read(&pageCount); err != nil || pageCount == 0 || pageCount > 4096 {
		return nil, fmt.Errorf("invalid Go FairPlay oracle page count")
	}
	for range pageCount {
		var address uint64
		if err := read(&address); err != nil || address%pageSize != 0 {
			return nil, fmt.Errorf("invalid Go FairPlay oracle page address")
		}
		if _, exists := result.pages[address]; exists {
			return nil, fmt.Errorf("duplicate Go FairPlay oracle page %#x", address)
		}
		page := make([]byte, pageSize)
		if _, err := io.ReadFull(stream, page); err != nil {
			return nil, err
		}
		result.pages[address] = page
	}
	var domainCount uint32
	if err := read(&domainCount); err != nil || domainCount > 64 {
		return nil, fmt.Errorf("invalid Go FairPlay oracle domain count")
	}
	for range domainCount {
		var key domainKey
		if err := read(&key.pc); err != nil {
			return nil, err
		}
		var registerBytes [1]byte
		if _, err := io.ReadFull(stream, registerBytes[:]); err != nil || registerBytes[0] >= 31 {
			return nil, fmt.Errorf("invalid Go FairPlay oracle domain register")
		}
		key.register = registerBytes[0]
		var reserved [7]byte
		if _, err := io.ReadFull(stream, reserved[:]); err != nil || reserved != [7]byte{} {
			return nil, fmt.Errorf("invalid Go FairPlay oracle domain envelope")
		}
		if _, exists := result.domains[key]; exists {
			return nil, fmt.Errorf("duplicate Go FairPlay oracle domain")
		}
		var values [256]uint64
		for index := range values {
			if err := read(&values[index]); err != nil {
				return nil, err
			}
			if index != 0 && values[index] <= values[index-1] {
				return nil, fmt.Errorf("Go FairPlay oracle domain is not ordered")
			}
		}
		result.domains[key] = values
	}
	var trailing [1]byte
	if count, err := stream.Read(trailing[:]); err != io.EOF || count != 0 {
		return nil, fmt.Errorf("Go FairPlay oracle model has trailing data")
	}
	return result, nil
}

type state struct {
	model    *model
	x        [31]uint64
	sp       uint64
	n, z     bool
	c, v     bool
	writable map[uint64][]byte
	touched  []uint64
	dirty    map[uint64]bool
}

func newState(value *model) *state {
	return &state{model: value, writable: make(map[uint64][]byte), dirty: make(map[uint64]bool)}
}

func (s *state) begin(block [16]byte) error {
	for _, address := range s.touched {
		copy(s.writable[address], s.model.pages[address])
		delete(s.dirty, address)
	}
	s.touched = s.touched[:0]
	s.x = s.model.registers
	s.sp = s.model.sp
	s.n, s.z, s.c, s.v = s.model.n, s.model.z, s.model.c, s.model.v
	return s.store(s.model.block, block[:])
}

func (s *state) page(address uint64, write bool) ([]byte, error) {
	base := address &^ (pageSize - 1)
	page := s.model.pages[base]
	if page == nil {
		return nil, fmt.Errorf("oracle memory address %#x is outside the model", address)
	}
	if !write {
		if writable := s.writable[base]; writable != nil {
			return writable, nil
		}
		return page, nil
	}
	writable := s.writable[base]
	if writable == nil {
		writable = append([]byte(nil), page...)
		s.writable[base] = writable
	}
	if !s.dirty[base] {
		s.dirty[base] = true
		s.touched = append(s.touched, base)
	}
	return writable, nil
}

func (s *state) load(address uint64, size int) (uint64, error) {
	if size != 1 && size != 4 && size != 8 {
		return 0, fmt.Errorf("unsupported oracle load size %d", size)
	}
	if address&(pageSize-1)+uint64(size) <= pageSize {
		page, err := s.page(address, false)
		if err != nil {
			return 0, err
		}
		offset := address & (pageSize - 1)
		switch size {
		case 1:
			return uint64(page[offset]), nil
		case 4:
			return uint64(binary.LittleEndian.Uint32(page[offset : offset+4])), nil
		default:
			return binary.LittleEndian.Uint64(page[offset : offset+8]), nil
		}
	}
	var buffer [8]byte
	for index := 0; index < size; index++ {
		value, err := s.load(address+uint64(index), 1)
		if err != nil {
			return 0, err
		}
		buffer[index] = byte(value)
	}
	return binary.LittleEndian.Uint64(buffer[:]), nil
}

func (s *state) store(address uint64, value []byte) error {
	for len(value) != 0 {
		page, err := s.page(address, true)
		if err != nil {
			return err
		}
		offset := address & (pageSize - 1)
		count := min(len(value), int(pageSize-offset))
		copy(page[offset:offset+uint64(count)], value[:count])
		address += uint64(count)
		value = value[count:]
	}
	return nil
}

func (s *state) storeValue(address, value uint64, size int) error {
	var buffer [8]byte
	switch size {
	case 1:
		buffer[0] = byte(value)
	case 4:
		binary.LittleEndian.PutUint32(buffer[:4], uint32(value))
	case 8:
		binary.LittleEndian.PutUint64(buffer[:], value)
	default:
		return fmt.Errorf("unsupported oracle store size %d", size)
	}
	return s.store(address, buffer[:size])
}

func (s *state) output() ([16]byte, error) {
	var result [16]byte
	for index := range result {
		value, err := s.load(s.model.block+uint64(index), 1)
		if err != nil {
			return result, err
		}
		result[index] = byte(value)
	}
	return result, nil
}

type faultKind uint8

const (
	faultNone faultKind = iota
	faultIndex
	faultPointer
)

type fault struct {
	pc         uint64
	register   uint8
	shift      uint8
	value      uint8
	kind       faultKind
	restore    bool
	tableBytes uint16
	entryBytes uint8
}

func (s *state) beforeFault(selected fault, pc uint64) (uint64, bool, error) {
	if selected.kind == faultNone || selected.pc != pc {
		return 0, false, nil
	}
	if selected.register >= 31 {
		return 0, false, fmt.Errorf("invalid oracle fault register")
	}
	old := s.x[selected.register]
	switch selected.kind {
	case faultIndex:
		if values, ok := s.model.domains[domainKey{pc: selected.pc, register: selected.register}]; ok {
			needle := uint64(uint32(old))
			low, high := 0, len(values)
			for low < high {
				middle := int(uint(low+high) >> 1)
				if values[middle] < needle {
					low = middle + 1
				} else {
					high = middle
				}
			}
			if low == len(values) || values[low] != needle {
				return 0, false, fmt.Errorf("index value %#x is outside the learned domain", needle)
			}
			s.x[selected.register] = values[low^int(selected.value)]
		} else {
			s.x[selected.register] = uint64(uint32(old) ^ uint32(selected.value)<<selected.shift)
		}
	case faultPointer:
		if selected.tableBytes == 0 || selected.entryBytes == 0 || selected.tableBytes&(selected.tableBytes-1) != 0 {
			return 0, false, fmt.Errorf("invalid pointer-fault geometry")
		}
		mask := uint64(selected.tableBytes - 1)
		base := old &^ mask
		offset := old - base
		if offset >= uint64(selected.tableBytes) || offset%uint64(selected.entryBytes) != 0 {
			return 0, false, fmt.Errorf("pointer fault %#x is outside its table", old)
		}
		position := offset / uint64(selected.entryBytes)
		s.x[selected.register] = base + (position^uint64(selected.value))*uint64(selected.entryBytes)
	default:
		return 0, false, fmt.Errorf("unsupported fault kind")
	}
	return old, selected.restore, nil
}

func (s *state) afterFault(selected fault, pc, old uint64, restore bool) {
	if restore && selected.pc == pc {
		s.x[selected.register] = old
	}
}

func (s *state) compare32(left, right uint32) {
	result := left - right
	s.n = result&0x80000000 != 0
	s.z = result == 0
	s.c = left >= right
	s.v = ((left ^ right) & (left ^ result) & 0x80000000) != 0
}

func (s *state) test32(value uint32) {
	s.n, s.z, s.c, s.v = value&0x80000000 != 0, value == 0, false, false
}

func (s *state) condition(name string) bool {
	switch name {
	case "eq":
		return s.z
	case "ne":
		return !s.z
	case "lo":
		return !s.c
	case "hi":
		return s.c && !s.z
	default:
		panic("unsupported generated condition: " + name)
	}
}

func rotateRight32(value uint32, amount uint32) uint32 {
	amount &= 31
	if amount == 0 {
		return value
	}
	return value>>amount | value<<(32-amount)
}

func mask32(width uint32) uint32 {
	if width >= 32 {
		return ^uint32(0)
	}
	return uint32(1)<<width - 1
}

func signExtend32(value uint32) uint64 { return uint64(int64(int32(value))) }

func checkModelBuild(value *model) error {
	if value.binaryHash != generatedBinaryHash {
		return fmt.Errorf("oracle model does not match generated fairplayd build")
	}
	return nil
}

func deterministicInput(index uint32) [16]byte {
	buffer := []byte("macOS FairPlay Go oracle input")
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], index)
	value := sha256.Sum256(append(buffer, encoded[:]...))
	var result [16]byte
	copy(result[:], value[:16])
	return result
}

var errUnsupportedCommand = errors.New("unsupported oracle protocol command")

type oracleServer struct {
	model   *model
	workers []*state
}

func newOracleServer(value *model, workerCount int) (*oracleServer, error) {
	if err := checkModelBuild(value); err != nil {
		return nil, err
	}
	if workerCount < 1 {
		workerCount = 1
	}
	result := &oracleServer{model: value, workers: make([]*state, workerCount)}
	for index := range result.workers {
		result.workers[index] = newState(value)
	}
	return result, nil
}

type job struct {
	block [16]byte
	meta  uint32
}

func (s *oracleServer) evaluate(worker *state, item job) ([16]byte, error) {
	selected, err := generatedFault(item.meta)
	if err != nil {
		return [16]byte{}, err
	}
	if err := worker.begin(item.block); err != nil {
		return [16]byte{}, err
	}
	if err := runGenerated(worker, selected); err != nil {
		return [16]byte{}, err
	}
	return worker.output()
}

func (s *oracleServer) evaluateBatch(items []job) ([][16]byte, error) {
	result := make([][16]byte, len(items))
	if len(s.workers) == 1 || len(items) < 2 {
		for index, item := range items {
			value, err := s.evaluate(s.workers[0], item)
			if err != nil {
				return nil, err
			}
			result[index] = value
		}
		return result, nil
	}
	type workerResult struct {
		err error
	}
	done := make(chan workerResult, len(s.workers))
	for workerIndex, worker := range s.workers {
		go func(workerIndex int, worker *state) {
			for index := workerIndex; index < len(items); index += len(s.workers) {
				value, err := s.evaluate(worker, items[index])
				if err != nil {
					done <- workerResult{err: err}
					return
				}
				result[index] = value
			}
			done <- workerResult{}
		}(workerIndex, worker)
	}
	for range s.workers {
		if value := <-done; value.err != nil {
			return nil, value.err
		}
	}
	return result, nil
}

func writeError(output *bufio.Writer, err error) error {
	message := []byte(err.Error())
	if err := output.WriteByte(1); err != nil {
		return err
	}
	if err := binary.Write(output, binary.LittleEndian, uint32(len(message))); err != nil {
		return err
	}
	_, err = output.Write(message)
	return err
}

func (s *oracleServer) serve(input io.Reader, output io.Writer) error {
	in := bufio.NewReaderSize(input, 1<<20)
	out := bufio.NewWriterSize(output, 1<<20)
	defer out.Flush()
	for {
		command, err := in.ReadByte()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		switch command {
		case 1:
			// rounds, decrypt, no reverse, unknown last-MC, fixed sites,
			// non-dynamic, deterministic random input.
			if _, err := out.Write([]byte{0, 10, 0, 0, 0, 0, 0, 1}); err != nil {
				return err
			}
		case 2:
			return out.Flush()
		case 3:
			var count uint32
			if err := binary.Read(in, binary.LittleEndian, &count); err != nil {
				return err
			}
			if count == 0 || count > 1<<20 {
				if err := writeError(out, fmt.Errorf("invalid oracle job count %d", count)); err != nil {
					return err
				}
				break
			}
			items := make([]job, count)
			for index := range items {
				if _, err := io.ReadFull(in, items[index].block[:]); err != nil {
					return err
				}
				if err := binary.Read(in, binary.LittleEndian, &items[index].meta); err != nil {
					return err
				}
			}
			values, err := s.evaluateBatch(items)
			if err != nil {
				if err := writeError(out, err); err != nil {
					return err
				}
				break
			}
			if err := out.WriteByte(0); err != nil {
				return err
			}
			for _, value := range values {
				if _, err := out.Write(value[:]); err != nil {
					return err
				}
			}
		case 7:
			var index uint32
			if err := binary.Read(in, binary.LittleEndian, &index); err != nil {
				return err
			}
			value := deterministicInput(index)
			if err := out.WriteByte(0); err != nil {
				return err
			}
			if _, err := out.Write(value[:]); err != nil {
				return err
			}
		case 8:
			if err := out.WriteByte(0); err != nil {
				return err
			}
		default:
			if err := writeError(out, fmt.Errorf("%w: %d", errUnsupportedCommand, command)); err != nil {
				return err
			}
		}
		if err := out.Flush(); err != nil {
			return err
		}
	}
}
