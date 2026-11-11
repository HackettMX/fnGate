package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func writeOK(w http.ResponseWriter, v interface{}) {
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "data": v})
}

func writeErr(w http.ResponseWriter, code int, format string, args ...interface{}) {
	writeJSON(w, code, map[string]interface{}{
		"ok":    false,
		"error": fmt.Sprintf(format, args...),
	})
}

func decodeJSON(r *http.Request, dst interface{}) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 4<<20))
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("请求体不是合法 JSON: %w", err)
	}
	return nil
}

func method(w http.ResponseWriter, r *http.Request, allowed ...string) bool {
	for _, m := range allowed {
		if r.Method == m {
			return true
		}
	}
	writeErr(w, http.StatusMethodNotAllowed, "不支持的请求方法 %s", r.Method)
	return false
}

// 以下导出包装供各业务模块复用同一套响应格式，避免模块间重复实现。
func WriteOK(w http.ResponseWriter, v interface{}) { writeOK(w, v) }

func WriteErr(w http.ResponseWriter, code int, format string, args ...interface{}) {
	writeErr(w, code, format, args...)
}

func DecodeJSON(r *http.Request, dst interface{}) error { return decodeJSON(r, dst) }

func MethodOK(w http.ResponseWriter, r *http.Request, allowed ...string) bool {
	return method(w, r, allowed...)
}
