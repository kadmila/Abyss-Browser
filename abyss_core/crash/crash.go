package crash

import (
	"os"
	"time"
)

func CrashLog(content string) {
	file, err := os.OpenFile("abyssnet_dll_crash_log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	file.WriteString(time.Now().Format("2006-01-02 15:04:05.999999 -0700 MST") + " " + content + "\n")
	file.Close()
}
