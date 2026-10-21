package app

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
)

// Detection is local and read-only. Installation is not proof of authentication;
// the first prompt reports login errors without starting a device flow.
func detectCopilotCLI() string {
	path, err := exec.LookPath("copilot")
	if err != nil {
		return ""
	}
	return path
}

// Ask the installed CLI's SDK protocol to resolve its normal login, including
// gh and credential-store sources. No prompt, token extraction or login flow.
func copilotLoginStatus(parent context.Context, executable string) string {
	raw, err := copilotRPC(parent, executable, "auth.getStatus")
	var status struct {
		IsAuthenticated *bool `json:"isAuthenticated"`
	}
	if err != nil || json.Unmarshal(raw, &status) != nil || status.IsAuthenticated == nil {
		return "status unavailable"
	}
	if *status.IsAuthenticated {
		return "logged in"
	}
	return "not logged in"
}

func copilotRPC(parent context.Context, executable, method string) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(parent, 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "--server", "--stdio", "--no-auto-update")
	cmd.WaitDelay = time.Second
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	defer func() { _ = in.Close(); cancel(); _ = cmd.Wait() }()
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":%q,"params":{}}`, method)
	if _, err := fmt.Fprintf(in, "Content-Length: %d\r\n\r\n%s", len(body), body); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(io.LimitReader(out, 1<<20))
	for {
		length := 0
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return nil, err
			}
			line = strings.TrimSpace(line)
			if line == "" {
				break
			}
			if key, value, ok := strings.Cut(line, ":"); ok && strings.EqualFold(key, "Content-Length") {
				length, _ = strconv.Atoi(strings.TrimSpace(value))
			}
		}
		if length <= 0 || length > 1<<20 {
			return nil, fmt.Errorf("invalid Copilot RPC frame")
		}
		raw := make([]byte, length)
		if _, err := io.ReadFull(reader, raw); err != nil {
			return nil, err
		}
		var response struct {
			ID     int
			Result json.RawMessage
		}
		if json.Unmarshal(raw, &response) != nil {
			return nil, fmt.Errorf("invalid Copilot RPC response")
		}
		if response.ID != 1 {
			continue
		}
		if len(response.Result) == 0 {
			return nil, fmt.Errorf("Copilot %s unavailable", method)
		}
		return response.Result, nil
	}
}

func copilotModels(ctx context.Context, executable string) ([]localModel, error) {
	raw, err := copilotRPC(ctx, executable, "models.list")
	if err != nil {
		return nil, err
	}
	return parseCopilotModels(raw)
}

func parseCopilotModels(raw []byte) ([]localModel, error) {
	var result struct {
		Models []struct {
			ID           string
			Policy       struct{ State string }
			Capabilities struct{ Type string }
		}
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	var models []localModel
	seen := map[string]bool{}
	for _, model := range result.Models {
		if model.ID == "" || seen[model.ID] || !localModelName.MatchString(model.ID) || (model.Policy.State != "" && model.Policy.State != "enabled") || (model.Capabilities.Type != "" && model.Capabilities.Type != "chat") {
			continue
		}
		seen[model.ID] = true
		models = append(models, localModel{Provider: "copilot", Model: model.ID})
	}
	if len(models) == 0 {
		return nil, fmt.Errorf("Copilot returned no available chat models")
	}
	return models, nil
}

func quickstartInference(mode, copilot string) (string, error) {
	switch mode {
	case "", "auto":
		return "", nil // Discovery only; the user must choose.
	case "copilot":
		if copilot == "" {
			return "", fmt.Errorf("Copilot CLI is not installed; install it or use --inference local")
		}
		return mode, nil
	case "local", "foundry":
		return mode, nil
	default:
		return "", fmt.Errorf("unknown inference %q; use auto, copilot, foundry, or local", mode)
	}
}

func copilotPrompt(ctx context.Context, executable, instructions, message string) (string, error) {
	return copilotPromptModel(ctx, executable, "auto", instructions+"\n\nUser message:\n"+message)
}

func copilotPromptModel(ctx context.Context, executable, model, prompt string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	// Avoid inheriting this checkout's instructions or working files. Credentials
	// remain in the user's normal Copilot environment; no credential copying.
	dir, err := fileaccess.PrivateTempDir("", "kmx-copilot-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	cmd := exec.CommandContext(ctx, executable, "-p", prompt, "--model", model, "--silent", "--stream", "off",
		"--output-format", "json", "--available-tools=kmx_tool_adapter_only", "--disable-builtin-mcps", "--no-custom-instructions", "--no-ask-user", "--no-auto-update")
	cmd.Dir = dir
	cmd.WaitDelay = time.Second
	out := &orkaBoundedBuffer{remaining: 1 << 20}
	diagnostics := &orkaBoundedBuffer{remaining: 64 << 10}
	cmd.Stdout, cmd.Stderr = out, diagnostics
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", fmt.Errorf("Copilot prompt failed: %w. Check `copilot login` and `copilot -p` in your terminal, or select /inference-local", err)
	}
	answer, err := copilotJSONAnswer(out.buffer.Bytes())
	if err != nil {
		return "", err
	}
	if answer == "" {
		return "", fmt.Errorf("Copilot returned no printable response")
	}
	return answer, nil
}

func copilotJSONAnswer(raw []byte) (string, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	answer := ""
	for {
		var event struct {
			Type string
			Data struct {
				Content      string
				ToolRequests []json.RawMessage
			}
			ExitCode int
		}
		err := decoder.Decode(&event)
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("invalid Copilot JSON output")
		}
		if event.Type == "assistant.message" {
			if len(event.Data.ToolRequests) > 0 {
				return "", fmt.Errorf("Copilot attempted a native tool outside the KMX adapter")
			}
			answer = event.Data.Content
		}
		if event.Type == "result" && event.ExitCode != 0 {
			return "", fmt.Errorf("Copilot reported a failed turn")
		}
	}
	return strings.TrimSpace(safeTerminal(answer)), nil
}

func (b *orkaChatBackend) copilotInstructionsFromAgent(ctx context.Context, raw []byte) (string, error) {
	var agent struct {
		Spec struct {
			SystemPrompt struct {
				Inline       string
				ConfigMapRef *struct{ Name, Key string }
			}
		}
	}
	if err := json.Unmarshal(raw, &agent); err != nil {
		return "", err
	}
	prompt := agent.Spec.SystemPrompt
	if prompt.ConfigMapRef != nil {
		raw, err := b.app.orkaCapture(ctx, nil, "-n", b.namespace, "get", "configmap", prompt.ConfigMapRef.Name, "-o", "json")
		if err != nil {
			return "", err
		}
		var cm struct{ Data map[string]string }
		if err := json.Unmarshal(raw, &cm); err != nil {
			return "", err
		}
		value, ok := cm.Data[prompt.ConfigMapRef.Key]
		if !ok {
			return "", fmt.Errorf("agent instruction ConfigMap key is missing")
		}
		return value, nil
	}
	return prompt.Inline, nil
}

func (b *orkaChatBackend) inferenceLabel() string {
	if b.app.chatInference == "foundry" && b.app.foundryClient != nil {
		return "Foundry · " + b.app.foundryClient.config.Deployment + " · Entra login · host HTTP tools"
	}
	if b.app.chatInference == "copilot" {
		return "Copilot CLI · " + b.app.copilotModel + " · KMX tool-call adapter"
	}
	return "Local Orka Provider · fresh Task and worker Job"
}
