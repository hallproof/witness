package forge

import (
	"context"
	"log/slog"

	"github.com/xraph/forge"
)

// forgeHandler is a slog.Handler that writes to a Forge logger, so witness
// and its adapters log where the rest of the app does.
type forgeHandler struct {
	l      forge.Logger
	fields []forge.Field
	prefix string
}

func newForgeLogger(l forge.Logger) *slog.Logger {
	return slog.New(&forgeHandler{l: l})
}

// Enabled is always true: the Forge logger applies its own level.
func (*forgeHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *forgeHandler) Handle(_ context.Context, r slog.Record) error {
	fields := make([]forge.Field, len(h.fields), len(h.fields)+r.NumAttrs())
	copy(fields, h.fields)
	r.Attrs(func(a slog.Attr) bool {
		fields = appendAttr(fields, h.prefix, a)
		return true
	})
	switch {
	case r.Level >= slog.LevelError:
		h.l.Error(r.Message, fields...)
	case r.Level >= slog.LevelWarn:
		h.l.Warn(r.Message, fields...)
	case r.Level >= slog.LevelInfo:
		h.l.Info(r.Message, fields...)
	default:
		h.l.Debug(r.Message, fields...)
	}
	return nil
}

func (h *forgeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	fields := append([]forge.Field(nil), h.fields...)
	for _, a := range attrs {
		fields = appendAttr(fields, h.prefix, a)
	}
	return &forgeHandler{l: h.l, fields: fields, prefix: h.prefix}
}

func (h *forgeHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &forgeHandler{l: h.l, fields: h.fields, prefix: h.prefix + name + "."}
}

// appendAttr adds a as a field, flattening groups into dotted keys.
func appendAttr(fields []forge.Field, prefix string, a slog.Attr) []forge.Field {
	v := a.Value.Resolve()
	if v.Kind() == slog.KindGroup {
		p := prefix
		if a.Key != "" {
			p += a.Key + "."
		}
		for _, g := range v.Group() {
			fields = appendAttr(fields, p, g)
		}
		return fields
	}
	if a.Key == "" {
		return fields
	}
	return append(fields, forge.F(prefix+a.Key, v.Any()))
}
