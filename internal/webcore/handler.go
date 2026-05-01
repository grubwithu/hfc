package webcore

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"

	"github.com/gin-gonic/gin"
	"github.com/grubwithu/orchestra/internal/analysis"
	"github.com/grubwithu/orchestra/internal/plugin"
)

type APIResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type CorpusReportReqBody struct {
	Fuzzer    string   `json:"fuzzer"`
	JobId     int      `json:"job_id"`
	JobBudget int      `json:"job_budget"`
	Identity  string   `json:"identity"`
	Corpus    []string `json:"corpus"`
	Period    string   `json:"period"`
}

func (s *Server) processCorpus(reqBody CorpusReportReqBody) {
	// Create plugin data with basic information
	ctx := context.Background()
	pluginData := &plugin.PluginData{
		Fuzzer: reqBody.Fuzzer,
		Corpus: reqBody.Corpus[0],
		Period: reqBody.Period,
		JobID:  reqBody.JobId,
		Budget: reqBody.JobBudget,
	}

	// tar all corpus to /opt/<job_id>.tgz
	tarPath := fmt.Sprintf("/opt/%d.tgz", reqBody.JobId)
	cmd := exec.Command("tar", "-czvf", tarPath, reqBody.Corpus[0])
	if err := cmd.Run(); err != nil {
		log.Printf("Error creating tarball: %v\n", err)
		return
	}

	// set corpus to tarPath
	pluginData.Corpus = tarPath

	// Process through plugin pipeline
	if s.PluginRegistry != nil {
		if err := s.PluginRegistry.ProcessAll(ctx, pluginData); err != nil {
			log.Printf("Error processing corpus data with plugins: %v\n", err)
		}
	}

	log.Printf("Processed corpus item %s for task %d.\n", reqBody.Corpus[0], reqBody.JobId)

	// rm - corpusDir
	os.RemoveAll(reqBody.Corpus[0])
}

type ReportCorpusResponse struct {
	JobId int `json:"job_id"`
}

func (s *Server) handleReportCorpus(c *gin.Context) {
	var report CorpusReportReqBody

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

	go func() {
		report.Corpus = []string{corpusDir}
		s.processCorpus(report)
		defer os.RemoveAll(corpusDir)
	}()

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Corpus report received successfully. Processing in background.",
	})

}

type PeekResultResBody struct {
	ConstraintGroups []analysis.ConstraintGroup          `json:"constraint_groups"`
	FuzzerScores     map[string]analysis.ConstraintScore `json:"fuzzer_scores"`
	FuzzerCovInc     map[string]int                      `json:"fuzzer_cov_inc"`
}

func (s *Server) handlePeekResult(c *gin.Context) {
	// Get results from all plugins using GetResults (not ProcessAll)
	ctx := context.Background()
	var pluginResults map[string]any
	if s.PluginRegistry != nil {
		if results, err := s.PluginRegistry.Results(ctx); err == nil {
			pluginResults = results
		}
	}

	// Add plugin results to the response
	responseData := map[string]any{
		"plugin_results": pluginResults,
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Results retrieved",
		Data:    responseData,
	})

}

type LogReqBody struct {
	Log string `json:"log"`
}

func (s *Server) handleLog(c *gin.Context) {

	var logReq LogReqBody
	if err := c.ShouldBindJSON(&logReq); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "Invalid request body: " + err.Error(),
		})
		return
	}
	// just print the log
	log.Println(logReq.Log)
	// return success
	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Log received successfully",
	})

}

func (s *Server) handleReady(c *gin.Context) {
	s.ReadyMutex.Lock()
	defer s.ReadyMutex.Unlock()
	if s.Ready {
		c.JSON(http.StatusOK, APIResponse{
			Success: true,
			Message: "Ready",
		})
	} else {
		c.JSON(http.StatusOK, APIResponse{
			Success: false,
			Message: "Not ready",
		})
	}
}
