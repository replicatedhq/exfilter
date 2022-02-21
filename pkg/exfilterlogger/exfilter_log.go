package exfilterlogger

import (
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

type EgressEvent struct {
	// EventTime time.Time
	Pid          uint32
	Saddr        string
	Daddr        string
	Data         string
	Msg          string
	Timestamp_ns time.Time
}

func InitLogger(logFilePath string) (*os.File, error) {
	// open a file
	f, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}

	// Log as JSON instead of the default ASCII formatter.
	logrus.SetFormatter(&logrus.JSONFormatter{})

	// Output to file.
	logrus.SetOutput(f)

	// logrus.SetLevel(logrus.DebugLevel)
	return f, nil
}

func LogEvent(event EgressEvent) error {
	logrus.WithFields(logrus.Fields{
		"PID":     event.Pid,
		"SAddr":   event.Saddr,
		"DAddr":   event.Daddr,
		"Payload": event.Data,
		"Message": event.Msg,
	}).Info(event.Msg)
	return nil
}

func DeinitLogger(f *os.File) {
	f.Close()
}
