package webcore

import (
	"log"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"time"

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
	ConstraintGroups []analysis.ConstraintGroup `json:"constraint_groups"`
}

type CorpusReport struct {
	Fuzzer   string   `json:"fuzzer"`
	Identity string   `json:"identity"`
	Corpus   []string `json:"corpus"`
}

func (s *Server) processCorpus(taskID TaskID, fuzzer string, corpus string) {

	workDir, err := os.MkdirTemp("", "hfc_work_")
	if err != nil {
		log.Printf("Error creating temporary work directory: %v\n", err)
		return
	}
	defer os.RemoveAll(workDir)
	profdataPath, err := analysis.RunOnceForProfdata(workDir, *s.Executable, corpus)
	if err != nil {
		log.Printf("Error running analysis on corpus item %s for task %s: %v\n", corpus, taskID, err)
		return
	}
	coverage, err := analysis.GetProgCov(workDir, *s.Executable, profdataPath)
	if err != nil {
		log.Printf("Error running analysis on corpus item %s for task %s: %v\n", corpus, taskID, err)
	}

	s.GlobalCovMutex.Lock()
	if s.GlobalCov == nil {
		s.GlobalCov = &coverage
	} else {
		s.GlobalCov.CorpusCount += coverage.CorpusCount
		for _, funcCoverage := range coverage.Functions {
			existing := false
			for i := range s.GlobalCov.Functions {
				if s.GlobalCov.Functions[i].Name == funcCoverage.Name {
					s.GlobalCov.Functions[i].Count += funcCoverage.Count
					existing = true
					break
				}
			}
			if !existing {
				s.GlobalCov.Functions = append(s.GlobalCov.Functions, funcCoverage)
			}
		}
	}

	constrains := analysis.IdentifyImportantConstraints(s.CallTree, s.GlobalCov)
	groups := analysis.GroupConstraintsByFunction(constrains, s.GlobalCov)
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].TotalImportance > groups[j].TotalImportance
	})

	s.GlobalCovMutex.Unlock()

	s.ConstraintGroupsMutex.Lock()
	s.ConstraintGroups = groups
	s.ConstraintGroupsMutex.Unlock()

	lineCov, err := analysis.GetLineCov(workDir, *s.Executable, profdataPath)
	if err != nil {
		log.Printf("Error running analysis on corpus item %s for task %s: %v\n", corpus, taskID, err)
		return
	}

	startTime := time.Now()
	score := analysis.CalculateFuzzerScore(lineCov, s.FileLineCovs, s.AST, s.SourceCode)
	log.Print(fuzzer, " score: ", score, " time passed: ", time.Since(startTime))

	s.FuzzerScoresMutex.Lock()
	s.FuzzerScores[fuzzer] = analysis.UpdateFuzzerScore(score, s.FuzzerScores[fuzzer])
	s.FuzzerScoresMutex.Unlock()

	log.Printf("Processed corpus item %s for task %s. Global corpus count: %d\n", corpus, taskID, s.GlobalCov.CorpusCount)

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

	// report.Corpus[0] is the path to the corpus file, print the tree of the directory
	// print the tree of the directory
	corpusDir, err := os.MkdirTemp("", "hfc_run_")
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: "Failed to create temporary directory",
		})
		return
	}

	for _, corpusItem := range report.Corpus {
		log.Println("Copying corpus item", corpusItem, "to", corpusDir)
		cmd := exec.Command("cp", "-r", corpusItem, corpusDir)
		if err := cmd.Run(); err != nil {
			log.Printf("Error copying corpus item %s to %s: %v\n", corpusItem, corpusDir, err)
			continue
		}
	}

	taskID, err := generateTaskID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: "Failed to generate task ID",
		})
		return
	}

	go func() {
		s.processCorpus(taskID, report.Fuzzer, corpusDir)
		defer os.RemoveAll(corpusDir)
	}()

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Corpus report received successfully. Processing in background.",
	})

}

func (s *Server) handlePeekResult(c *gin.Context) {
	fuzzer := c.Param("fuzzer")

	s.ConstraintGroupsMutex.Lock()

	result := ResultBody{}

	s.FuzzerScoresMutex.Lock()
	if s.FuzzerScores[fuzzer] == nil {
		log.Println("default constraint group sequence")
		result.ConstraintGroups = s.ConstraintGroups
	} else {
		log.Println("fuzzer-based constraint group sequence")
		result.ConstraintGroups = analysis.SortConstraintGroup(s.ConstraintGroups, s.FuzzerScores[fuzzer], s.AST, s.SourceCode)
	}
	s.FuzzerScoresMutex.Unlock()

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Constraint groups retrieved",
		Data:    result,
	})

	s.ConstraintGroupsMutex.Unlock()

}
