package analysis

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Define a struct to match the structure of your YAML file
// You'll need to adjust this based on your actual YAML content

type Callsite struct {
	Src string `yaml:"Src"`
	Dst string `yaml:"Dst"`
}

type FunctionStatic struct {
	FunctionName          string     `yaml:"functionName"`
	FunctionSourceFile    string     `yaml:"functionSourceFile"`
	LinkageType           string     `yaml:"linkageType"`
	FunctionLinenumber    int        `yaml:"functionLinenumber"`
	FunctionLinenumberEnd int        `yaml:"functionLinenumberEnd"`
	FunctionDepth         int        `yaml:"functionDepth"`
	ReturnType            string     `yaml:"returnType"`
	ArgCount              int        `yaml:"argCount"`
	ArgTypes              []string   `yaml:"argTypes"`
	ConstantsTouched      []string   `yaml:"constantsTouched"` // Assuming strings, adjust as needed
	ArgNames              []string   `yaml:"argNames"`
	BBCount               int        `yaml:"BBCount"`
	ICount                int        `yaml:"ICount"`
	EdgeCount             int        `yaml:"EdgeCount"`
	CyclomaticComplexity  int        `yaml:"CyclomaticComplexity"`
	FunctionsReached      []string   `yaml:"functionsReached"` // Assuming strings, adjust as needed
	FunctionUses          int        `yaml:"functionUses"`
	BranchProfiles        []string   `yaml:"BranchProfiles"` // Assuming strings, adjust as needed
	Callsites             []Callsite `yaml:"Callsites"`      // Assuming strings, adjust as needed

	TotalCyclomaticComplexity int
}

type ProgramStaticData struct {
	FuzzerFileName string `yaml:"Fuzzer filename"`
	AllFunctions   struct {
		FunctionListName string            `yaml:"Function list name"`
		Elements         []*FunctionStatic `yaml:"Elements"`
	} `yaml:"All functions"`
}

func (funcStatic *FunctionStatic) calculateTotalCyclomaticComplexity(functionMap map[string]*FunctionStatic) int {
	// Check if the result is already cached
	if funcStatic.TotalCyclomaticComplexity != 0 {
		return funcStatic.TotalCyclomaticComplexity
	}
	res := funcStatic.CyclomaticComplexity
	for _, funcName := range funcStatic.FunctionsReached {
		if funcStatic, ok := functionMap[funcName]; ok {
			res += funcStatic.calculateTotalCyclomaticComplexity(functionMap)
		}
	}
	// Cache the result
	funcStatic.TotalCyclomaticComplexity = res
	return res
}

// ParseYAMLFile parses a YAML file and returns the parsed data
func ParseStaticDataFromYAML(filePath string) (*ProgramStaticData, error) {
	// Read the YAML file

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading YAML file: %w", err)
	}

	// Parse the YAML data into our struct
	var staticData ProgramStaticData
	err = yaml.Unmarshal(data, &staticData)
	if err != nil {
		return nil, fmt.Errorf("error parsing YAML file: %w", err)
	}

	var functions map[string]*FunctionStatic = make(map[string]*FunctionStatic)
	for _, funcStatic := range staticData.AllFunctions.Elements {
		functions[funcStatic.FunctionName] = funcStatic
	}

	functions["LLVMFuzzerTestOneInput"].calculateTotalCyclomaticComplexity(functions)

	return &staticData, nil
}
