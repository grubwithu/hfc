package prerun

/**
 * Prerun plugin handles initial corpus processing
 * Prerun plugin must be the first plugin in the pipeline
 **/

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/grubwithu/orchestra/internal/analysis"
	"github.com/grubwithu/orchestra/internal/plugin"
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/cpp"
)

const PLUGIN_NAME = "prerun"

type PrerunData struct {
	CallTree    analysis.CallTree
	ProgProfile *analysis.ProgramProfile
	DebugInfo   analysis.DebugInfo
	Cov         int
	ProgCov     analysis.ProgCovData
	LineCov     []analysis.FileLineCov
	AST         map[string]*sitter.Tree
	ASTMutex    sync.Mutex
	SourceCode  map[string][]byte
	FuncScores  map[string]analysis.ConstraintScore
}

// Plugin handles initial corpus processing
type Plugin struct {
	config        plugin.PluginConfig
	initData      PrerunData
	isInitialized bool
}

// NewPlugin creates a new prerun plugin
func NewPlugin() *Plugin {
	return &Plugin{
		isInitialized: false,
	}
}

// Name returns the plugin name
func (p *Plugin) Name() string {
	return PLUGIN_NAME
}

// Require checks if the plugin should process the given data
// Prerun plugin always processes data
func (p *Plugin) Require(data *plugin.PluginData) bool {
	return true
}

// Init initializes the plugin with executable and generates initial coverage data
func (p *Plugin) Init(ctx context.Context, config plugin.PluginConfig) error {
	p.config = config

	// Get executable from config
	if config.Executable == "" {
		p.Log(ctx, "executable not provided in config\n")
		return nil
	}
	executable := config.Executable

	prefix := strings.TrimSpace(config.FuzzIntroPrefix)
	profilePath := prefix + ".yaml"

	// Parse YAML with timing
	start := time.Now()
	progProfile, err := analysis.ParseProfileFromYAML(profilePath, config.SrcPathMatch)
	if err != nil {
		p.Log(ctx, "Error parsing YAML: %v\n", err)
		return err
	}
	p.Log(ctx, "ParseProfileFromYAML took %v\n", time.Since(start))

	// Parse call tree with timing
	callTreePath := prefix
	start = time.Now()
	callTree, err := analysis.ParseCallTreeFromData(callTreePath, progProfile)
	if err != nil {
		p.Log(ctx, "Error parsing call tree data: %v\n", err)
		return err
	}
	p.Log(ctx, "ParseCallTreeFromData took %v\n", time.Since(start))

	// Parse debug info with timing
	debugInfoPath := prefix + ".debug_info"
	start = time.Now()
	debugInfo, err := analysis.ParseDebugInfoFromFile(debugInfoPath)
	if err != nil {
		p.Log(ctx, "Error parsing debug info: %v\n", err)
		return err
	}
	p.Log(ctx, "ParseDebugInfoFromFile took %v\n", time.Since(start))

	// 1. Create a temp directory for initial corpus
	corpusDir, err := os.MkdirTemp("", "hfc_corpus_")
	if err != nil {
		p.Log(ctx, "Error creating corpus directory: %v\n", err)
		return err
	}
	defer os.RemoveAll(corpusDir)

	// 2. Create seed file
	seedPath := filepath.Join(corpusDir, "seed")
	if err := os.WriteFile(seedPath, []byte("0"), 0644); err != nil {
		p.Log(ctx, "Error writing seed file: %v\n", err)
		return err
	}

	// 3. Create a temp work directory
	workDir, err := os.MkdirTemp("", "hfc_work_")
	if err != nil {
		p.Log(ctx, "Error creating work directory: %v\n", err)
		return err
	}
	defer os.RemoveAll(workDir)

	// 4. Run analysis to generate profdata
	start = time.Now()
	cov, profdataPath, err := analysis.RunOnceForProfdata(workDir, executable, corpusDir)
	if err != nil {
		p.Log(ctx, "Error running RunOnceForProfdata: %v\n", err)
		return err
	}
	p.Log(ctx, "RunOnceForProfdata took %v\n", time.Since(start))

	// 5. Get program coverage data
	start = time.Now()
	progCovData, err := analysis.GetProgCov(workDir, executable, profdataPath)
	if err != nil {
		p.Log(ctx, "Error getting program coverage data: %v\n", err)
		return err
	}
	p.Log(ctx, "GetProgCov took %v\n", time.Since(start))

	// 6. Get line coverage data
	start = time.Now()
	fileLineCovs, err := analysis.GetLineCov(workDir, executable, profdataPath)
	if err != nil {
		p.Log(ctx, "Error getting line coverage data: %v\n", err)
		return err
	}
	p.Log(ctx, "GetLineCov took %v\n", time.Since(start))

	// Reset coverage for fresh start
	for i := range fileLineCovs {
		fileLineCovs[i].ResetCov()
	}

	// 7. Parse the code in files
	start = time.Now()
	ast := map[string]*sitter.Tree{}
	sourceCode := map[string][]byte{}
	parser := sitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(cpp.GetLanguage()) // C++ is a superset of C
	for _, file := range fileLineCovs {
		code := file.GetOriginCode()
		sourceCode[file.File] = code
		tree, _ := parser.ParseCtx(context.Background(), nil, code)
		ast[file.File] = tree
	}
	p.Log(ctx, "Parse code files took %v\n", time.Since(start))

	// Analyze all reachable functions in the call tree
	start = time.Now()
	funcScores := make(map[string]analysis.ConstraintScore)
	processed := make(map[string]bool)
	totalScores := analysis.ConstraintScore{
		analysis.CT_VALUE_COMPARISON:     0,
		analysis.CT_BITWISE_OPERATION:    0,
		analysis.CT_STRING_MATCH:         0,
		analysis.CT_ARITHMETIC_OPERATION: 0,
		analysis.CT_COMPOUND_OPERATION:   0,
	}
	for _, node := range callTree.Nodes {
		if node.FunctionProfile == nil {
			continue
		}
		funcName := node.FunctionProfile.FunctionName
		// p.Log(ctx, "Analyzing function %s\n", funcName)
		if processed[funcName] {
			continue
		}
		processed[funcName] = true
		scores := analysis.AnalyzeFunctionScore(funcName, node.FunctionProfile.FunctionSourceFile, ast, sourceCode, fileLineCovs)
		if scores != nil {
			funcScores[funcName] = scores
			p.Log(ctx, "  %s: val_cmp=%.2f, bit_opr=%.2f, str_mat=%.2f, art_opr=%.2f, comp_opr=%.2f\n",
				funcName,
				scores[analysis.CT_VALUE_COMPARISON],
				scores[analysis.CT_BITWISE_OPERATION],
				scores[analysis.CT_STRING_MATCH],
				scores[analysis.CT_ARITHMETIC_OPERATION],
				scores[analysis.CT_COMPOUND_OPERATION])
			for ct, score := range scores {
				totalScores[ct] += score
			}
		}
	}
	p.Log(ctx, "Analyze function scores took %v, analyzed %d functions\n", time.Since(start), len(funcScores))
	p.Log(ctx, "Total scores: val_cmp=%.2f, bit_opr=%.2f, str_mat=%.2f, art_opr=%.2f, comp_opr=%.2f\n",
		totalScores[analysis.CT_VALUE_COMPARISON],
		totalScores[analysis.CT_BITWISE_OPERATION],
		totalScores[analysis.CT_STRING_MATCH],
		totalScores[analysis.CT_ARITHMETIC_OPERATION],
		totalScores[analysis.CT_COMPOUND_OPERATION])

	// Store initialization data
	p.initData = PrerunData{
		Cov:         cov,
		ProgCov:     progCovData,
		LineCov:     fileLineCovs,
		AST:         ast,
		SourceCode:  sourceCode,
		CallTree:    *callTree,
		ProgProfile: progProfile,
		DebugInfo:   *debugInfo,
		FuncScores:  funcScores,
	}
	p.isInitialized = true

	if p.config.Verbose {
		p.Log(ctx, "Init: coverage=%d, funcs=%d, files=%d\n", cov, len(progCovData.Functions), len(fileLineCovs))
	} else {
		p.Log(ctx, "Initialized\n")
	}
	return nil
}

// GetInitData returns the initialization data for other plugins
func (p *Plugin) GetInitData() *PrerunData {
	return &p.initData
}

// Process processes the corpus and generates coverage data
func (p *Plugin) Process(ctx context.Context, data *plugin.PluginData) error {
	// Get executable from config
	if p.config.Executable == "" {
		return nil
	}
	executable := p.config.Executable

	// Create temporary work directory
	workDir, err := os.MkdirTemp("", "hfc_work_")
	if err != nil {
		p.Log(ctx, "Error creating work directory: %v\n", err)
		return err
	}
	defer os.RemoveAll(workDir)

	// Run analysis to generate profdata
	cov, profdataPath, err := analysis.RunOnceForProfdata(workDir, executable, data.Corpus)
	if err != nil {
		p.Log(ctx, "Error running RunOnceForProfdata: %v\n", err)
		return err
	}

	// Get program coverage data
	progCovData, err := analysis.GetProgCov(workDir, executable, profdataPath)
	if err != nil {
		p.Log(ctx, "Error getting program coverage data: %v\n", err)
		return err
	}

	// Get line coverage data
	lineCov, err := analysis.GetLineCov(workDir, executable, profdataPath)
	if err != nil {
		p.Log(ctx, "Error getting line coverage data: %v\n", err)
		return err
	}

	// Store results in PluginData
	prerunResult := &p.initData
	prerunResult.Cov = cov
	prerunResult.ProgCov = progCovData
	prerunResult.LineCov = lineCov

	data.Data[PLUGIN_NAME] = prerunResult

	if p.config.Verbose {
		p.Log(ctx, "Process: fuzzer=%s, corpus=%s, coverage=%d, funcs=%d, files=%d\n", data.Fuzzer, data.Corpus, cov, len(progCovData.Functions), len(lineCov))
	} else {
		p.Log(ctx, "Processed corpus for fuzzer=%s\n", data.Fuzzer)
	}

	return nil
}

// Prerun plugin should return nothing
func (p *Plugin) Result(ctx context.Context, previousResults map[string]any) (any, error) {
	return nil, nil
}

// Cleanup cleans up the plugin resources
func (p *Plugin) Cleanup(ctx context.Context) error {
	log.Println("PrerunPlugin cleanup")
	return nil
}

// Priority returns the plugin priority
func (p *Plugin) Priority() int {
	return 1000 // Highest priority to run first
}

func (p *Plugin) Log(ctx context.Context, format string, args ...any) {
	log.Printf("[PRERUN] "+format, args...)
}
