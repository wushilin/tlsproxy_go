package logging

import "fmt"

type LOG_LEVEL uint8

const (
	Debug LOG_LEVEL = iota
	Info
	Warn
	Error
	Fatal
)

func (s LOG_LEVEL) String() string {
	switch s {
	case Debug:
		return "DEBUG"
	case Info:
		return "INFO "
	case Warn:
		return "WARN "
	case Error:
		return "ERROR"
	case Fatal:
		return "FATAL"
	}
	return "FATAL"
}

var GLOBAL_LOG_LEVEL = Debug

func logf(level LOG_LEVEL, msg_format string, args ...interface{}) {
	if level <= GLOBAL_LOG_LEVEL {
		return
	}
	if len(args) == 0 {
		fmt.Printf("%s ", level)
		fmt.Println(msg_format)
	} else {
		fmt.Printf("%s ", level)
		fmt.Printf(msg_format, args...)
		fmt.Println()
	}
}

var DEBUG = func(msg_format string, args ...interface{}) {
	logf(Debug, msg_format, args...)
}

var INFO = func(msg_format string, args ...interface{}) {
	logf(Info, msg_format, args...)
}
var WARN = func(msg_format string, args ...interface{}) {
	logf(Warn, msg_format, args...)
}

var ERROR = func(msg_format string, args ...interface{}) {
	logf(Error, msg_format, args...)
}

var FATAL = func(msg_format string, args ...interface{}) {
	logf(Fatal, msg_format, args...)
}

func SetLogLevel(level int) {
	GLOBAL_LOG_LEVEL = LOG_LEVEL(level)
}
