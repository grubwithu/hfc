package coordinator

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/grubwithu/orchestra/internal/contracts"
)

const maxRequestBytes = 8 << 20

func NewHandler(state *State) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /v1/state", func(writer http.ResponseWriter, _ *http.Request) {
		version, coverage := state.Snapshot()
		writeJSON(writer, http.StatusOK, map[string]any{
			"schema_version":  contracts.SchemaVersion,
			"state_version":   version,
			"global_coverage": coverage,
		})
	})
	mux.HandleFunc("POST /v1/jobs/dispatch", func(writer http.ResponseWriter, request *http.Request) {
		var job contracts.JobDispatch
		if err := decodeJSON(writer, request, &job); err != nil {
			writeError(writer, http.StatusBadRequest, err)
			return
		}
		dispatched, err := state.Dispatch(job)
		if err != nil {
			writeError(writer, http.StatusConflict, err)
			return
		}
		writeJSON(writer, http.StatusCreated, dispatched)
	})
	mux.HandleFunc("POST /v1/jobs/complete", func(writer http.ResponseWriter, request *http.Request) {
		var result contracts.JobResult
		if err := decodeJSON(writer, request, &result); err != nil {
			writeError(writer, http.StatusBadRequest, err)
			return
		}
		feedback, err := state.Merge(result)
		if err != nil {
			writeError(writer, http.StatusConflict, err)
			return
		}
		writeJSON(writer, http.StatusOK, feedback)
	})
	return mux
}

func decodeJSON(writer http.ResponseWriter, request *http.Request, destination any) error {
	request.Body = http.MaxBytesReader(writer, request.Body, maxRequestBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode JSON request: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request must contain one JSON value")
	}
	return nil
}

func writeError(writer http.ResponseWriter, status int, err error) {
	writeJSON(writer, status, map[string]any{
		"schema_version": contracts.SchemaVersion,
		"error":          err.Error(),
	})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
