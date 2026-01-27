//go:build !debug

package and

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
}

func (s *ANDStatistics) B(i int) {}

func (s *ANDStatistics) W(i int) {}

func (s *ANDStatistics) String() string {
	return "disabled in release build"
}
