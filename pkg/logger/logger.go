// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Monkfish
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package logger

import (
	"os"

	"github.com/sirupsen/logrus"
)

type LogConfig struct {
	Level      string
	Output     string
	FilePath   string
	MaxSize    int
	MaxBackups int
	MaxAge     int
}

var Log *logrus.Logger

func InitLogger(config *LogConfig) *logrus.Logger {
	log := logrus.New()

	switch config.Level {
	case "debug":
		log.SetLevel(logrus.DebugLevel)
	case "info":
		log.SetLevel(logrus.InfoLevel)
	case "warn":
		log.SetLevel(logrus.WarnLevel)
	case "error":
		log.SetLevel(logrus.ErrorLevel)
	default:
		log.SetLevel(logrus.InfoLevel)
	}

	log.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: "2006-01-02 15:04:05",
	})

	if config.Output == "file" {
		file, err := os.OpenFile(config.FilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err == nil {
			log.SetOutput(file)
		} else {
			log.SetOutput(os.Stdout)
			log.Warnf("Failed to open log file, using stdout: %v", err)
		}
	} else {
		log.SetOutput(os.Stdout)
	}

	Log = log
	return log
}

func GetLogger() *logrus.Logger {
	return Log
}

func Debug(args ...interface{})                       { Log.Debug(args...) }
func Debugf(format string, args ...interface{})       { Log.Debugf(format, args...) }
func Info(args ...interface{})                        { Log.Info(args...) }
func Infof(format string, args ...interface{})        { Log.Infof(format, args...) }
func Warn(args ...interface{})                        { Log.Warn(args...) }
func Warnf(format string, args ...interface{})        { Log.Warnf(format, args...) }
func Error(args ...interface{})                       { Log.Error(args...) }
func Errorf(format string, args ...interface{})       { Log.Errorf(format, args...) }
func Fatal(args ...interface{})                       { Log.Fatal(args...) }
func Fatalf(format string, args ...interface{})       { Log.Fatalf(format, args...) }
