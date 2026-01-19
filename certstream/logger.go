package certstream

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
)

// Logger is the interface for logging
type Logger interface {
	Debug(format string, v ...interface{})
	Error(format string, v ...interface{})
	Info(format string, v ...interface{})
}

// defaultLogger is the default logger implementation
type defaultLogger struct {
	debug bool
}

// NewDefaultLogger creates a new default logger
func NewDefaultLogger(debug bool) Logger {
	return &defaultLogger{debug: debug}
}

func (l *defaultLogger) Debug(format string, v ...interface{}) {
	if l.debug {
		fmt.Printf("[DEBUG] "+format+"\n", v...)
	}
}

func (l *defaultLogger) Error(format string, v ...interface{}) {
	errorMsg := fmt.Sprintf(format, v...)

	// List of errors to suppress
	suppressedErrors := []string{
		"read limited at 32769 bytes",
		"failed to read frame payload: unexpected EOF",
		"failed to get reader: failed to read frame header: unexpected EOF",
		"received close frame: status = StatusNormalClosure",
	}

	for _, suppressed := range suppressedErrors {
		if strings.Contains(errorMsg, suppressed) {
			return
		}
	}

	if color.NoColor {
		fmt.Printf("[ERROR] "+format+"\n", v...)
	} else {
		color.New(color.FgRed).Printf("[ERROR] "+format+"\n", v...)
	}
}

func (l *defaultLogger) Info(format string, v ...interface{}) {
	if color.NoColor {
		fmt.Printf("[INFO] "+format+"\n", v...)
	} else {
		color.New(color.FgCyan).Printf("[INFO] "+format+"\n", v...)
	}
}
