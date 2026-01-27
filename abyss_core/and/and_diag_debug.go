//go:build debug

package and

import (
	"strconv"
	"strings"
)

type ANDStatistics struct {
	JN_TX  int
	JOK_TX int
	JDN_TX int
	JNI_TX int
	MEM_TX int
	SJN_TX int
	CRR_TX int
	RST_TX int
	SOA_TX int
	SOD_TX int

	JN_RX  int
	JOK_RX int
	JDN_RX int
	JNI_RX int
	MEM_RX int
	SJN_RX int
	CRR_RX int
	RST_RX int
	SOA_RX int
	SOD_RX int

	_b [36]int
	_w [85]int
}

func (s *ANDStatistics) B(i int) {
	s._b[i]++
}

func (s *ANDStatistics) W(i int) {
	s._w[i]++
}

// three-digit notation
func __tdn(i int) string {
	if i < 0 {
		return "---"
	}

	if i < 10 {
		return "   " + strconv.Itoa(i)
	} else if i < 100 {
		return "  " + strconv.Itoa(i)
	}

	v := i
	m := 0
	for v >= 100 {
		v = v / 10
		m++
	}

	if m > 26 {
		return " FFF"
	}
	return " " + string(rune('A'+m-1)) + strconv.Itoa(v)
}

func (s *ANDStatistics) String() string {
	var sb strings.Builder
	sb.WriteString(" JN JOK JDN JNI MEM SJN CRR RST SOA SOD\n")
	sb.WriteString(__tdn(s.JN_TX))
	sb.WriteString(__tdn(s.JOK_TX))
	sb.WriteString(__tdn(s.JDN_TX))
	sb.WriteString(__tdn(s.JNI_TX))
	sb.WriteString(__tdn(s.MEM_TX))
	sb.WriteString(__tdn(s.SJN_TX))
	sb.WriteString(__tdn(s.CRR_TX))
	sb.WriteString(__tdn(s.RST_TX))
	sb.WriteString(__tdn(s.SOA_TX))
	sb.WriteString(__tdn(s.SOD_TX))
	sb.WriteString("\n")
	sb.WriteString(__tdn(s.JN_RX))
	sb.WriteString(__tdn(s.JOK_RX))
	sb.WriteString(__tdn(s.JDN_RX))
	sb.WriteString(__tdn(s.JNI_RX))
	sb.WriteString(__tdn(s.MEM_RX))
	sb.WriteString(__tdn(s.SJN_RX))
	sb.WriteString(__tdn(s.CRR_RX))
	sb.WriteString(__tdn(s.RST_RX))
	sb.WriteString(__tdn(s.SOA_RX))
	sb.WriteString(__tdn(s.SOD_RX))
	sb.WriteString("\n")

	for i, b := range s._b {
		sb.WriteString(__tdn(b))
		if i%10 == 9 {
			sb.WriteString("\n")
		}
	}
	sb.WriteString("\n")
	for i, w := range s._w {
		sb.WriteString(__tdn(w))
		if i%10 == 9 {
			sb.WriteString("\n")
		}
	}

	return sb.String()
}
