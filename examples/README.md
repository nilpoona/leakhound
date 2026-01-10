# Configuration Examples

Copy these configurations to your project root as `.leakhound.yaml`.

- [zap.yaml](zap.yaml) - go.uber.org/zap
- [zerolog.yaml](zerolog.yaml) - github.com/rs/zerolog
- [logrus.yaml](logrus.yaml) - github.com/sirupsen/logrus

## Usage

```bash
# Download and use a configuration file
curl -o .leakhound.yaml https://raw.githubusercontent.com/nilpoona/leakhound/main/examples/zap.yaml
leakhound ./...
```

Or specify a custom path:

```bash
leakhound --config path/to/config.yaml ./...
```

## Configuration Format

The configuration file uses YAML format with the following structure:

```yaml
targets:
  - package: "go.uber.org/zap"           # Package path
    functions:                            # Package-level functions (optional)
      - "Info"
      - "Debug"
    methods:                              # Methods on specific types (optional)
      - receiver: "*Logger"               # Receiver type (* for pointer)
        names:                            # Method names
          - "Info"
          - "Debug"
```

At least one of `functions` or `methods` must be specified for each target.

## Notes

- Standard library packages (`log`, `log/slog`, `fmt`) are supported by default without configuration
- Package paths must be lowercase with allowed characters: `a-z`, `0-9`, `.`, `-`, `/`
- Function and method names must be valid Go identifiers
- Receiver types can be pointer (`*Logger`) or value (`Logger`)
