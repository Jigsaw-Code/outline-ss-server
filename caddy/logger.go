// Copyright 2024 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddy

import (
	"context"
	"log/slog"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type logger struct {
	zap *zap.Logger
}

func (l *logger) Enabled(ctx context.Context, level slog.Level) bool {
	return l.zap.Check(toZapLevel(level), "") != nil
}

func (l *logger) LogAttrs(ctx context.Context, level slog.Level, msg string, attrs ...slog.Attr) {
	fields := toZapFields(attrs)
	l.zap.Log(toZapLevel(level), msg, fields...)

}

func toZapLevel(level slog.Level) zapcore.Level {
	switch level {
	case slog.LevelInfo:
		return zapcore.InfoLevel
	case slog.LevelWarn:
		return zapcore.WarnLevel
	case slog.LevelError:
		return zapcore.ErrorLevel
	default:
		return zapcore.DebugLevel
	}
}

func toZapFields(attrs []slog.Attr) []zapcore.Field {
	fields := make([]zapcore.Field, 0, len(attrs))
	var field zapcore.Field
	for _, attr := range attrs {
		field = zap.Any(attr.Key, attr.Value)
		fields = append(fields, field)
	}

	return fields
}
