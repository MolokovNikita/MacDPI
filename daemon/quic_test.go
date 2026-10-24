package main

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestQUICInitialClassification(t *testing.T) {
	if len(flowsealQUICFake) != 1200 || !quicInitial(flowsealQUICFake) {
		t.Fatal("pinned QUIC pattern is not an Initial")
	}
	v2 := append([]byte(nil), flowsealQUICFake...)
	v2[0] = v2[0]&^0x30 | 0x10
	binary.BigEndian.PutUint32(v2[1:], 0x6b3343cf)
	if !quicInitial(v2) {
		t.Fatal("QUIC v2 Initial rejected")
	}
	for _, mutate := range []func([]byte){
		func(b []byte) { b[0] = 0x40 },
		func(b []byte) { b[0] = b[0]&^0x30 | 0x20 },
		func(b []byte) { b[0] = b[0]&^0x30 | 0x10 },
		func(b []byte) { binary.BigEndian.PutUint32(b[1:], 0) },
		func(b []byte) { b[5] = 21 },
		func(b []byte) { b[14] = 21 },
		func(b []byte) { b[15] = 0xff },
	} {
		b := append([]byte(nil), flowsealQUICFake...)
		mutate(b)
		if quicInitial(b) {
			t.Fatal("unrelated or malformed UDP classified as QUIC Initial")
		}
	}
	for _, n := range []int{0, 1, 5, 100, 1199} {
		if quicInitial(flowsealQUICFake[:n]) {
			t.Fatal("truncated Initial accepted")
		}
	}
}
func TestQUICBurstsAreBoundedAndExcludeApplicationData(t *testing.T) {
	p := quicUDPPolicy{}
	now := time.Now()
	if !p.before(now, flowsealQUICFake) {
		t.Fatal("initial burst missing")
	}
	if p.before(now.Add(100*time.Millisecond), flowsealQUICFake) {
		t.Fatal("burst flood")
	}
	if p.before(now.Add(time.Second), []byte{0x40, 1}) {
		t.Fatal("application packet triggered fakes")
	}
	for i := 1; i <= 2; i++ {
		if !p.before(now.Add(time.Duration(i)*time.Second), flowsealQUICFake) {
			t.Fatal("bounded retry missing")
		}
	}
	if p.before(now.Add(20*time.Second), flowsealQUICFake) {
		t.Fatal("unbounded retries")
	}
}
func FuzzQUICInitial(f *testing.F) {
	f.Add(flowsealQUICFake)
	f.Add([]byte{0xc0})
	f.Fuzz(func(t *testing.T, b []byte) { quicInitial(b) })
}
