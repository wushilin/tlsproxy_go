package logging

import (
	"os"

	"github.com/rs/zerolog"
)

var l = zerolog.New(zerolog.ConsoleWriter{
	Out:        os.Stderr,
	TimeFormat: "2006-01-02T15:04:05Z07:00"}).With().Timestamp().Logger()

var INFO = l.Info
var DEBUG = l.Debug
var WARN = l.Warn
var ERROR = l.Error
var TRACE = l.Trace
var FATAL = l.Fatal
var LEVEL = zerolog.InfoLevel

func SetLoggingLevel(level int) {
	zerolog.SetGlobalLevel(zerolog.Level(level))
}
