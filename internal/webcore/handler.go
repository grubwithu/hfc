package webcore

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/grubwithu/hfc/internal/analysis"
)

func generateTaskID() (TaskID, error) {
	bytes := make([]byte, 16)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return TaskID(hex.EncodeToString(bytes)), nil
}

type ProcessResult struct {
	ToDelete []string `json:"toDelete"`

	Status string
}

type TaskID string

type CorpusReport struct {
	Fuzzer   string   `json:"fuzzer"`
	Identity string   `json:"identity"`
	Corpus   []string `json:"corpus"`
}

type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func (s *Server) processCorpus(taskID TaskID, report CorpusReport) {
	if len(report.Corpus) == 0 {
		s.results[taskID] = ProcessResult{
			Status:   StatusFailed,
			ToDelete: nil,
		}
	} else {
		if len(report.Corpus) > 1 {
			fmt.Printf("Warning: multiple corpus items received for task %s. Only the first item will be processed.\n", taskID)
		}
		coverage, err := analysis.RunOnce(*s.programPath, report.Corpus[0])
		if err != nil {
			fmt.Printf("Error running analysis on corpus item %s for task %s: %v\n", report.Corpus[0], taskID, err)
			s.results[taskID] = ProcessResult{
				Status:   StatusFailed,
				ToDelete: nil,
			}
		}
		callTree, err := analysis.BuildCallTree(s.staticData)
		if err != nil {
			fmt.Printf("Error building call tree for task %s: %v\n", taskID, err)
			s.results[taskID] = ProcessResult{
				Status:   StatusFailed,
				ToDelete: nil,
			}
		}

		callTree.OverlayWithCoverage(&coverage)

		s.results[taskID] = ProcessResult{
			Status:   StatusCompleted,
			ToDelete: nil,
		}

	}
}

type ReportCorpusResponse struct {
	TaskID TaskID `json:"taskId"`
}

func (s *Server) handleReportCorpus(c *gin.Context) {
	var report CorpusReport

	if err := c.ShouldBindJSON(&report); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "Invalid request body: " + err.Error(),
		})
		return
	}

	taskID, err := generateTaskID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: "Failed to generate task ID",
		})
		return
	}

	s.mutex.Lock()
	s.results[taskID] = ProcessResult{
		Status: StatusProcessing,
	}
	s.mutex.Unlock()

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Corpus report received successfully. Processing in background.",
		Data:    ReportCorpusResponse{TaskID: taskID},
	})

	go s.processCorpus(taskID, report)
}

func (s *Server) handlePeekResult(c *gin.Context) {
	taskID := TaskID(c.Param("taskId"))

	s.mutex.Lock()
	result, exists := s.results[taskID]
	s.mutex.Unlock()

	if !exists {
		c.JSON(http.StatusNotFound, APIResponse{
			Success: false,
			Message: "Task not found",
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Task status retrieved",
		Data:    result,
	})

	s.mutex.Lock()
	delete(s.results, taskID)
	defer s.mutex.Unlock()
}
