package webcore

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/grubwithu/hfc/internal/analysis"
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/cpp"
)

const (
	StatusProcessing = "processing"
	StatusCompleted  = "completed"
	StatusFailed     = "failed"
)

type Server struct {
	Router *gin.Engine
	Port   int

	AST        map[string]*sitter.Tree
	Executable *string
	CallTree   *analysis.CallTree

	GlobalCovMutex        sync.Mutex // mutex for global function coverage
	GlobalCov             *analysis.ProgCovData
	ConstraintGroupsMutex sync.Mutex // mutex for constraint groups
	ConstraintGroups      []analysis.ConstraintGroup
	FileLineCovsMutex     sync.Mutex
	FileLineCovs          []analysis.FileLineCov
	FuzzerScoresMutex     sync.Mutex
	FuzzerScores          map[string]analysis.FuzzerScore
}

func NewServer(port int, progPath *string, callTree *analysis.CallTree) *Server {
	// 1. create a temp directory
	corpusDir, err := os.MkdirTemp("", "hfc_corpus_")
	if err != nil {
		log.Fatal("error creating temporary corpus directory: ", err)
	}
	defer os.RemoveAll(corpusDir)
	workDir, err := os.MkdirTemp("", "hfc_work_")
	if err != nil {
		log.Fatal("error creating temporary work directory: ", err)
	}
	defer os.RemoveAll(workDir)

	// 2. echo 0 > tempDir/seed
	seedPath := filepath.Join(corpusDir, "seed")
	if err := os.WriteFile(seedPath, []byte("0"), 0644); err != nil {
		log.Fatal("error writing seed file: ", err)
	}

	// 3. use RunOnce in dynamic.go
	profdataPath, err := analysis.RunOnceForProfdata(workDir, *progPath, corpusDir)
	if err != nil {
		log.Fatal("error running executable file: ", err)
	}

	// 3. use GetLineCov in dynamic.go
	fileLineCovs, err := analysis.GetLineCov(workDir, *progPath, profdataPath)
	if err != nil {
		log.Fatal("error getting line coverage: ", err)
	}

	for i := range fileLineCovs {
		fileLineCovs[i].ResetCov()
	}

	// 4. parse the code in files
	ast := map[string]*sitter.Tree{}
	parser := sitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(cpp.GetLanguage()) // C++ is a superset of C
	for _, file := range fileLineCovs {
		code := file.GetOriginCode()
		tree, _ := parser.ParseCtx(context.Background(), nil, code)
		ast[file.File] = tree
	}

	router := gin.Default()
	server := &Server{
		Router:       router,
		Port:         port,
		Executable:   progPath,
		CallTree:     callTree,
		AST:          ast,
		FileLineCovs: fileLineCovs,
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
