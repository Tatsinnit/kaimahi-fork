package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/config"
	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
)

// Agent locations contain routing metadata, never model credential values.
// A private kubeconfig snapshot preserves AKS exec authentication and survives
// deletion of the temporary kubeconfig used during lift.
type agentLocation struct {
	Agent         string `json:"agent"`
	Namespace     string `json:"namespace"`
	Context       string `json:"context"`
	Kubeconfig    string `json:"kubeconfig,omitempty"`
	Cluster       string `json:"cluster,omitempty"`
	Subscription  string `json:"subscription,omitempty"`
	ResourceGroup string `json:"resourceGroup,omitempty"`
}

func agentLocationsDir() (string, error) {
	dir, err := config.StateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "agentconfigs"), nil
}

func (l agentLocation) key() string { return l.Context + "\x00" + l.Namespace + "\x00" + l.Agent }

func loadAgentLocations() ([]agentLocation, error) {
	dir, err := agentLocationsDir()
	if err != nil {
		return nil, err
	}
	var locations []agentLocation
	err = forEachPrivateAgentFile(dir, ".json", func(name string, raw []byte) error {
		var location agentLocation
		if err := json.Unmarshal(raw, &location); err != nil {
			return fmt.Errorf("invalid agent location %s", name)
		}
		if location.Agent == "" || location.Namespace == "" || location.Context == "" {
			return fmt.Errorf("incomplete agent location %s", name)
		}
		locations = append(locations, location)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(locations, func(i, j int) bool { return locations[i].key() < locations[j].key() })
	return locations, nil
}

func writeAgentLocation(location agentLocation, kubeconfig []byte) (agentLocation, error) {
	dir, err := agentLocationsDir()
	if err != nil {
		return location, err
	}
	if err = fileaccess.EnsurePrivatePath(dir); err != nil {
		return location, err
	}
	key := fmt.Sprintf("%x", sha256.Sum256([]byte(location.key())))
	if len(kubeconfig) > 0 {
		location.Kubeconfig = filepath.Join(dir, key+".kubeconfig")
		if err = writePrivateAgentFile(location.Kubeconfig, kubeconfig); err != nil {
			return location, err
		}
	}
	raw, err := json.MarshalIndent(location, "", "  ")
	if err != nil {
		return location, err
	}
	return location, writePrivateAgentFile(filepath.Join(dir, key+".json"), raw)
}

// writePrivateAgentFile (private_state_{unix,windows}.go) atomically
// replaces a private file: stage, write, flush, close, then rename over the
// destination with replace semantics. Never delete the destination first and
// introduce a missing-file window.

func appAtAgentLocation(source *App, location agentLocation) *App {
	app := *source
	cfg := *source.Cfg
	runner := *source.Run
	cfg.KubeContext, cfg.ContextSource = location.Context, config.SourceFlag
	runner.Env = append([]string(nil), runner.Env...)
	if location.Kubeconfig != "" {
		filtered := runner.Env[:0]
		for _, env := range runner.Env {
			if !strings.HasPrefix(env, "KUBECONFIG=") {
				filtered = append(filtered, env)
			}
		}
		runner.Env = append(filtered, "KUBECONFIG="+location.Kubeconfig)
	}
	app.Cfg, app.Run = &cfg, &runner
	app.chatClusterName = location.Cluster
	app.guarded = false
	return &app
}

func (b *orkaChatBackend) connectAgentLocation(ctx context.Context, location agentLocation) error {
	app := appAtAgentLocation(b.app, location)
	raw, err := app.orkaCapture(ctx, nil, "-n", location.Namespace, "get", "agents.core.orka.ai", location.Agent, "-o", "json")
	if err != nil {
		return err
	}
	var object orkaObject
	if json.Unmarshal(raw, &object) != nil || object.Metadata.Name != location.Agent || object.Metadata.Namespace != location.Namespace || object.Metadata.UID == "" || object.Metadata.Generation < 1 {
		return fmt.Errorf("selected Agent returned no valid identity")
	}
	waitCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if err = app.waitOrkaReady(waitCtx, location.Namespace, orkaIdentity{Kind: "Agent", Name: location.Agent, UID: object.Metadata.UID, Generation: object.Metadata.Generation}); err != nil {
		return err
	}
	b.Close()
	app.chatInference = "local" // Use the selected cluster's configured Provider.
	b.app, b.agent, b.namespace = app, location.Agent, location.Namespace
	return nil
}
