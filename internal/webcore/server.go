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
	router *gin.Engine
	port   int

	programPath *string
	staticData  *analysis.ProgramStaticData

	mutex   sync.Mutex // mutex for results
	results map[TaskID]ProcessResult
}

func NewServer(port int, programPath *string, staticData *analysis.ProgramStaticData) *Server {
	router := gin.Default()
	server := &Server{
		router:      router,
		port:        port,
		programPath: programPath,
		staticData:  staticData,
		results:     make(map[TaskID]ProcessResult),
	}
	server.setupRoutes()
	return server
}

func (s *Server) setupRoutes() {
	s.router.POST("/reportCorpus", s.handleReportCorpus)
	s.router.GET("/peekResult/:taskId", s.handlePeekResult)
}

func (s *Server) Start() error {
	addr := fmt.Sprintf(":%d", s.port)
	fmt.Printf("Starting HTTP server on %s\n", addr)
	return s.router.Run(addr)
}
