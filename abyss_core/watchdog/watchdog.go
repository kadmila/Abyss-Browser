package watchdog

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/kadmila/Abyss-Browser/abyss_core/config"
	"github.com/phuslu/log"
)

var handle_count atomic.Int32
var handle_count_print_threshold atomic.Int32
var null_handle_closed_count atomic.Int32

func Init() {
	err := os.MkdirAll("log", os.ModePerm)
	if err != nil {
		panic(err)
	}
	logFile, err := os.OpenFile("log/"+time.Now().Format("0102_150405")+"_abyss_net.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}

	log.DefaultLogger = log.Logger{
		Level: log.InfoLevel,

		Writer: &log.ConsoleWriter{
			Writer:    logFile,
			Formatter: timeMS8Formatter,
		},
	}

	handle_count_print_threshold.Store(4)
	Info("start")
}

func timeMS8Formatter(w io.Writer, a *log.FormatterArgs) (int, error) {
	// Local wall-clock time for the moment the record is written.
	timestamp := time.Now().Local().Format("04:05.00000000") // mm:ss.ffffffff

	// If a stack was attached (e.g. log.Error().Stack().Msg(...)),
	// print it on a separate line.
	if len(a.Stack) > 0 {
		return fmt.Fprintf(
			w,
			"%s %-5s %s %s\n%s",
			timestamp, a.Level, a.Caller, a.Message, a.Stack,
		)
	}

	return fmt.Fprintf(
		w,
		"%s | %-5s %s\n",
		timestamp, a.Level, a.Message,
	)
}

func InfoV(head string, o any) {
	Info(head + formatFlatLine(o))
}

func Info(msg string) {
	if config.DEBUG {
		log.Info().Msg(msg)
	}
}

func Warn(msg string) {
	log.Warn().Msg(msg)
}

func Error(err error) {
	log.Error().Msg(err.Error())
}

func Fatal(msg string) {
	log.Fatal().Msg(msg)
}

func CountHandleExport() {
	handle_count.Add(1)

	current_threshhold := handle_count_print_threshold.Load()
	handle_count := handle_count.Load()

	if handle_count > current_threshhold*2 {
		handle_count_print_threshold.Store(current_threshhold * 2)
		Info("open handle count: " + strconv.Itoa(int(handle_count)))
	}
}
func CountHandleRelease() {
	handle_count.Add(-1)

	current_threshhold := handle_count_print_threshold.Load()
	handle_count := handle_count.Load()
	if handle_count < current_threshhold/2 && current_threshhold > 4 {
		handle_count_print_threshold.Store(current_threshhold / 2)
		Info("open handle count: " + strconv.Itoa(int(handle_count)))
	}
}
func CountNullHandleRelease() {
	null_handle_closed_count.Add(1)
	Warn("null handle close: " + strconv.Itoa(int(null_handle_closed_count.Load())))
}
