package webcore

import (
	"fmt"
	"log"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/grubwithu/hfc/internal/analysis"
)

const (
	StatusProcessing = "processing"
	StatusCompleted  = "completed"
	StatusFailed     = "failed"
)

type Server struct {
	Router *gin.Engine
	Port   int

	ProgramPath *string
	CallTree    *analysis.CallTree

	GlobalCoverageMutex   sync.Mutex // mutex for global function coverage
	GlobalCoverage        *analysis.ProgramCoverageData
	ConstraintGroupsMutex sync.Mutex // mutex for constraint groups
	ConstraintGroups      []analysis.ConstraintGroup
}

func NewServer(port int, programPath *string, callTree *analysis.CallTree) *Server {
	router := gin.Default()
	server := &Server{
		Router:      router,
		Port:        port,
		ProgramPath: programPath,
		CallTree:    callTree,
	}
	server.setupRoutes()
	return server
}

func (s *Server) setupRoutes() {
	s.Router.POST("/reportCorpus", s.handleReportCorpus)
	s.Router.GET("/peekResult", s.handlePeekResult)
}

func (s *Server) Start() error {
	addr := fmt.Sprintf(":%d", s.Port)
	log.Printf("Starting HTTP server on %s\n", addr)
	return s.Router.Run(addr)
}
