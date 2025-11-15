package webcore

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/grubwithu/hfc/internal/analysis"
)

func generateTaskID() (TaskID, error) {
	return TaskID(uuid.New().String()), nil
}

type TaskID string

type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type ResultBody struct {
	ConstraintGroups *[]analysis.ConstraintGroup `json:"constraint_groups"`
}

type CorpusReport struct {
	Fuzzer   string   `json:"fuzzer"`
	Identity string   `json:"identity"`
	Corpus   []string `json:"corpus"`
}

func (s *Server) processCorpus(taskID TaskID, report CorpusReport) {
	if len(report.Corpus) >= 1 {
		if len(report.Corpus) > 1 {
			log.Printf("Warning: multiple corpus items received for task %s. Only the first item will be processed.\n", taskID)
		}
		coverage, err := analysis.RunOnce(*s.ProgramPath, report.Corpus[0])
		if err != nil {
			log.Printf("Error running analysis on corpus item %s for task %s: %v\n", report.Corpus[0], taskID, err)
		}

		s.GlobalCoverageMutex.Lock()
		if s.GlobalCoverage == nil {
			s.GlobalCoverage = &coverage
		} else {
			s.GlobalCoverage.CorpusCount += coverage.CorpusCount
			for _, funcCoverage := range coverage.Functions {
				existing := false
				for i := range s.GlobalCoverage.Functions {
					if s.GlobalCoverage.Functions[i].Name == funcCoverage.Name {
						s.GlobalCoverage.Functions[i].Count += funcCoverage.Count
						existing = true
						break
					}
				}
				if !existing {
					s.GlobalCoverage.Functions = append(s.GlobalCoverage.Functions, funcCoverage)
				}
			}
		}

		constrains := analysis.IdentifyImportantConstraints(s.CallTree, s.GlobalCoverage)
		group := analysis.GroupConstraintsByFunction(constrains, s.GlobalCoverage)

		s.GlobalCoverageMutex.Unlock()

		s.ConstraintGroupsMutex.Lock()
		s.ConstraintGroups = group
		s.ConstraintGroupsMutex.Unlock()

		log.Printf("Processed corpus item %s for task %s. Global corpus count: %d\n", report.Corpus[0], taskID, s.GlobalCoverage.CorpusCount)

	}
}

type ReportCorpusResponse struct {
	TaskID TaskID `json:"task_id"`
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

	if len(report.Corpus) == 0 {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "Corpus is empty",
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

	go s.processCorpus(taskID, report)

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Corpus report received successfully. Processing in background.",
	})

}

func (s *Server) handlePeekResult(c *gin.Context) {

	s.ConstraintGroupsMutex.Lock()

	result := ResultBody{
		ConstraintGroups: &s.ConstraintGroups,
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Constraint groups retrieved",
		Data:    result,
	})

	s.ConstraintGroupsMutex.Unlock()

}
