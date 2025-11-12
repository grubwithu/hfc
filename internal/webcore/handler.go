package webcore

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/grubwithu/hfc/internal/analysis"
)

func generateTaskID() (TaskID, error) {
	return TaskID(uuid.New().String()), nil
}

type ProcessResult struct {
	ConstraintGroups []analysis.ConstraintGroup `json:"constraint_groups"`
	Status           string
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
		s.Results[taskID] = ProcessResult{
			Status: StatusFailed,
		}
	} else {
		if len(report.Corpus) > 1 {
			fmt.Printf("Warning: multiple corpus items received for task %s. Only the first item will be processed.\n", taskID)
		}
		coverage, err := analysis.RunOnce(*s.ProgramPath, report.Corpus[0])
		if err != nil {
			fmt.Printf("Error running analysis on corpus item %s for task %s: %v\n", report.Corpus[0], taskID, err)
			s.Results[taskID] = ProcessResult{
				Status: StatusFailed,
			}
		}

		constraints := analysis.IdentifyImportantConstraints(s.CallTree, &coverage)

		constraintGroups := analysis.GroupConstraintsByFunction(constraints, &coverage)

		s.Results[taskID] = ProcessResult{
			Status:           StatusCompleted,
			ConstraintGroups: constraintGroups,
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

	s.Mutex.Lock()
	s.Results[taskID] = ProcessResult{
		Status: StatusProcessing,
	}
	s.Mutex.Unlock()

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Corpus report received successfully. Processing in background.",
		Data:    ReportCorpusResponse{TaskID: taskID},
	})

	go s.processCorpus(taskID, report)
}

func (s *Server) handlePeekResult(c *gin.Context) {
	taskID := TaskID(c.Param("taskId"))

	s.Mutex.Lock()
	result, exists := s.Results[taskID]
	s.Mutex.Unlock()

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

	s.Mutex.Lock()
	delete(s.Results, taskID)
	defer s.Mutex.Unlock()
}
