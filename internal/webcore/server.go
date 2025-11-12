package webcore

import (
	"fmt"
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

	Mutex   sync.Mutex // mutex for results
	Results map[TaskID]ProcessResult
}

func NewServer(port int, programPath *string, callTree *analysis.CallTree) *Server {
	router := gin.Default()
	server := &Server{
		Router:      router,
		Port:        port,
		ProgramPath: programPath,
		CallTree:    callTree,
		Results:     make(map[TaskID]ProcessResult),
	}
	server.setupRoutes()
	return server
}

func (s *Server) setupRoutes() {
	s.Router.POST("/reportCorpus", s.handleReportCorpus)
	s.Router.GET("/peekResult/:taskId", s.handlePeekResult)
}

func (s *Server) Start() error {
	addr := fmt.Sprintf(":%d", s.Port)
	fmt.Printf("Starting HTTP server on %s\n", addr)
	return s.Router.Run(addr)
}
