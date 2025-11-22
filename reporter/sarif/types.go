package sarif

// Document represents the root SARIF document
type Document struct {
	Version string `json:"version"` // "2.1.0"
	Schema  string `json:"$schema"` // URI to SARIF schema
	Runs    []Run  `json:"runs"`
}

// Run represents an analysis run
type Run struct {
	Tool                     Tool                    `json:"tool"`
	Results                  []Result                `json:"results"`
	AutomationDetails        *AutomationDetails      `json:"automationDetails,omitempty"`
	VersionControlProvenance []VersionControlDetails `json:"versionControlProvenance,omitempty"`
}

// VersionControlDetails represents version control information
type VersionControlDetails struct {
	RepositoryURI string `json:"repositoryUri,omitempty"` // Repository URL
	RevisionID    string `json:"revisionId,omitempty"`    // Commit hash
	Branch        string `json:"branch,omitempty"`        // Current branch name
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
	ID                   string        `json:"id"`   // "LH0001"
	Name                 string        `json:"name"` // "SensitiveVariableLogged"
	ShortDescription     MessageString `json:"shortDescription"`
	FullDescription      MessageString `json:"fullDescription,omitempty"`
	Help                 MessageString `json:"help,omitempty"`
	HelpURI              string        `json:"helpUri,omitempty"` // URL to detailed rule documentation
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
	ContextRegion    *Region          `json:"contextRegion,omitempty"` // Surrounding context lines
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

// Rule ID constants for SARIF output
const (
	RuleIDSensitiveVar    = "LH0001"
	RuleIDSensitiveCall   = "LH0002"
	RuleIDSensitiveStruct = "LH0003"
	RuleIDSensitiveField  = "LH0004"
)

// ruleIDMapping maps detector rule IDs to SARIF conventional format (tool prefix + numeric code)
var ruleIDMapping = map[string]string{
	"sensitive-var":    RuleIDSensitiveVar,
	"sensitive-call":   RuleIDSensitiveCall,
	"sensitive-struct": RuleIDSensitiveStruct,
	"sensitive-field":  RuleIDSensitiveField,
}

// ToSARIFRuleID converts a detector rule ID to SARIF conventional format
func ToSARIFRuleID(detectorRuleID string) string {
	if sarifID, ok := ruleIDMapping[detectorRuleID]; ok {
		return sarifID
	}
	return detectorRuleID // fallback to original if not mapped
}

// BuildRules returns all rule descriptors for SARIF output
func BuildRules() []ReportingDescriptor {
	return []ReportingDescriptor{
		{
			ID:   RuleIDSensitiveVar,
			Name: "SensitiveVariableLogged",
			ShortDescription: MessageString{
				Text: "Variable containing sensitive data is logged",
			},
			FullDescription: MessageString{
				Text: "A variable that contains data from a field tagged with sensitive:\"true\" is passed to a logging function.",
			},
			Help: MessageString{
				Text: "Avoid logging variables that contain sensitive information. Consider redacting or removing the sensitive data before logging.",
			},
			HelpURI: "https://github.com/nilpoona/leakhound#" + RuleIDSensitiveVar,
			DefaultConfiguration: Configuration{
				Level: "error",
			},
		},
		{
			ID:   RuleIDSensitiveCall,
			Name: "SensitiveFunctionCallLogged",
			ShortDescription: MessageString{
				Text: "Function call returning sensitive data is logged",
			},
			FullDescription: MessageString{
				Text: "A function call that returns sensitive data (from a field tagged with sensitive:\"true\") is passed to a logging function.",
			},
			Help: MessageString{
				Text: "Avoid logging function return values that contain sensitive information. Store the result in a variable and redact sensitive fields before logging.",
			},
			HelpURI: "https://github.com/nilpoona/leakhound#" + RuleIDSensitiveCall,
			DefaultConfiguration: Configuration{
				Level: "error",
			},
		},
		{
			ID:   RuleIDSensitiveStruct,
			Name: "SensitiveStructLogged",
			ShortDescription: MessageString{
				Text: "Struct containing sensitive fields is logged",
			},
			FullDescription: MessageString{
				Text: "An entire struct that contains fields tagged with sensitive:\"true\" is passed to a logging function.",
			},
			Help: MessageString{
				Text: "Avoid logging entire structs that contain sensitive fields. Log only the non-sensitive fields individually.",
			},
			HelpURI: "https://github.com/nilpoona/leakhound#" + RuleIDSensitiveStruct,
			DefaultConfiguration: Configuration{
				Level: "error",
			},
		},
		{
			ID:   RuleIDSensitiveField,
			Name: "SensitiveFieldLogged",
			ShortDescription: MessageString{
				Text: "Sensitive struct field is logged",
			},
			FullDescription: MessageString{
				Text: "A struct field tagged with sensitive:\"true\" is directly accessed and passed to a logging function.",
			},
			Help: MessageString{
				Text: "Avoid logging fields marked as sensitive. Remove the field from the log call or redact its value.",
			},
			HelpURI: "https://github.com/nilpoona/leakhound#" + RuleIDSensitiveField,
			DefaultConfiguration: Configuration{
				Level: "error",
			},
		},
	}
}
