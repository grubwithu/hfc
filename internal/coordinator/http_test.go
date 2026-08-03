package coordinator

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/grubwithu/orchestra/internal/contracts"
)

func TestHTTPVerticalSlice(t *testing.T) {
	handler := NewHandler(New("model-1"))
	dispatch := contracts.JobDispatch{JobID: "job-1", ModelID: "model-1", FuzzerID: "libfuzzer"}
	response := serveJSON(t, handler, "/v1/jobs/dispatch", dispatch)
	if response.Code != http.StatusCreated {
		t.Fatalf("dispatch status = %d, body=%s", response.Code, response.Body.String())
	}

	result := contracts.JobResult{JobID: "job-1", OutputUnionBitmap: []uint32{9, 4, 9}}
	response = serveJSON(t, handler, "/v1/jobs/complete", result)
	if response.Code != http.StatusOK {
		t.Fatalf("complete status = %d, body=%s", response.Code, response.Body.String())
	}
	var feedback contracts.JobFeedback
	if err := json.Unmarshal(response.Body.Bytes(), &feedback); err != nil {
		t.Fatal(err)
	}
	assertEdges(t, "novel", feedback.NovelDeltaBitmap, []uint32{4, 9})

	request := httptest.NewRequest(http.MethodGet, "/v1/state", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("state status = %d", response.Code)
	}
}

func TestHTTPRejectsUnknownFields(t *testing.T) {
	handler := NewHandler(New("model-1"))
	request := httptest.NewRequest(http.MethodPost, "/v1/jobs/dispatch", bytes.NewBufferString(`{"job_id":"job","unknown":true}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body=%s", response.Code, response.Body.String())
	}
}

func serveJSON(t *testing.T, handler http.Handler, path string, value any) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(data))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
