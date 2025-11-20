package sarif

// Document represents the root SARIF document
type Document struct {
	Version string `json:"version"` // "2.1.0"
	Schema  string `json:"$schema"` // URI to SARIF schema
	Runs    []Run  `json:"runs"`
}

// Run represents an analysis run
type Run struct {
	Tool              Tool               `json:"tool"`
	Results           []Result           `json:"results"`
	AutomationDetails *AutomationDetails `json:"automationDetails,omitempty"`
}

// AutomationDetails represents automation information for the run
type AutomationDetails struct {
	ID   string `json:"id,omitempty"`   // Unique identifier for the automation run
	GUID string `json:"guid,omitempty"` // Globally unique identifier
}

// Tool represents tool information
type Tool struct {
	Driver Driver `json:"driver"`
}

// Driver represents the analysis tool driver
type Driver struct {
	Name            string                `json:"name"`               // "leakhound"
	FullName        string                `json:"fullName,omitempty"` // Full display name
	InformationURI  string                `json:"informationUri"`     // GitHub repo
	Version         string                `json:"version"`            // Tool version
	SemanticVersion string                `json:"semanticVersion"`    // SemVer
	Rules           []ReportingDescriptor `json:"rules"`
}

// ReportingDescriptor represents a rule definition
type ReportingDescriptor struct {
	ID                   string        `json:"id"`   // "sensitive-var"
	Name                 string        `json:"name"` // "SensitiveVariableLogged"
	ShortDescription     MessageString `json:"shortDescription"`
	FullDescription      MessageString `json:"fullDescription,omitempty"`
	Help                 MessageString `json:"help,omitempty"`
	DefaultConfiguration Configuration `json:"defaultConfiguration"`
}

// MessageString represents a message with text
type MessageString struct {
	Text string `json:"text"`
}

// Configuration represents rule configuration
type Configuration struct {
	Level string `json:"level"` // "error", "warning", "note"
}

// Result represents an analysis result
type Result struct {
	RuleID              string            `json:"ruleId"`
	Message             Message           `json:"message"`
	Locations           []Location        `json:"locations"`
	Level               string            `json:"level,omitempty"`               // "error", "warning", "note"
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"` // Stable fingerprints for result matching
}

// Message represents a result message
type Message struct {
	Text string `json:"text"`
}

// Location represents a location in source code
type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

// PhysicalLocation represents physical location information
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region"`
}

// ArtifactLocation represents a file location
type ArtifactLocation struct {
	URI       string `json:"uri"`                 // Relative file path
	URIBaseID string `json:"uriBaseId,omitempty"` // "%SRCROOT%"
}

// Region represents a region within a file
type Region struct {
	StartLine   int      `json:"startLine"`
	StartColumn int      `json:"startColumn,omitempty"`
	EndLine     int      `json:"endLine,omitempty"`
	EndColumn   int      `json:"endColumn,omitempty"`
	Snippet     *Snippet `json:"snippet,omitempty"`
}

// Snippet represents a code snippet
type Snippet struct {
	Text string `json:"text"`
}
