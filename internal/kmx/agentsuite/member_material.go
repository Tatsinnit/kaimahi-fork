package agentsuite

import (
	"bytes"
	"context"
	"errors"

	agentsuite "github.com/agent-primitives/suite"
)

var (
	ErrMemberMaterial = errors.New("verified suite member material is invalid")
	ErrMemberNotFound = errors.New("verified suite member was not found")
)

// MemberMaterial is the public AgentSuite projection shared by the read-only
// library and KMX's stricter native loader. Agent retains no file-map aliases.
type MemberMaterial struct {
	ArtifactDigest         string
	GraphDigest            string
	SuiteName              string
	MemberID               string
	MemberDescriptor       agentsuite.Descriptor
	Description            string
	Instructions           []byte
	InstructionsDescriptor agentsuite.Descriptor
	Model                  agentsuite.ModelRequirement
	Agent                  agentsuite.Agent
}

// ProjectMember rechecks the selected public descriptors in an already
// validated, caller-owned file snapshot. It does not interpret KMX metadata,
// cases, policies, runtime profiles, bindings, or execution authority.
func ProjectMember(ctx context.Context, files map[string][]byte, artifactDigest, memberID string) (MemberMaterial, error) {
	if err := ctx.Err(); err != nil {
		return MemberMaterial{}, err
	}
	if !agentsuite.IsValidDigest(artifactDigest) || memberID == "" {
		return MemberMaterial{}, ErrMemberMaterial
	}
	rootBytes, ok := files["agentsuite.json"]
	if !ok {
		return MemberMaterial{}, ErrMemberMaterial
	}
	var suite agentsuite.Suite
	if agentsuite.Unmarshal(rootBytes, &suite) != nil {
		return MemberMaterial{}, ErrMemberMaterial
	}
	graphDigest, err := agentsuite.Digest(rootBytes)
	if err != nil {
		return MemberMaterial{}, ErrMemberMaterial
	}
	var refs []agentsuite.ManifestRef
	for _, ref := range suite.Agents {
		if ref.ID == memberID {
			refs = append(refs, ref)
		}
	}
	if len(refs) == 0 {
		return MemberMaterial{}, ErrMemberNotFound
	}
	if len(refs) != 1 {
		return MemberMaterial{}, ErrMemberMaterial
	}
	ref := refs[0]
	memberBytes, ok := files[ref.Path]
	if !ok || ref.Descriptor.MediaType != agentsuite.MediaTypeAgent || !agentsuite.MatchesCanonicalDescriptor(memberBytes, ref.Descriptor) {
		return MemberMaterial{}, ErrMemberMaterial
	}
	var member agentsuite.Agent
	if agentsuite.Unmarshal(memberBytes, &member) != nil || member.ID != ref.ID || member.Instructions.Descriptor.MediaType != agentsuite.MediaTypeInstructions {
		return MemberMaterial{}, ErrMemberMaterial
	}
	instructions, ok := files[member.Instructions.Path]
	if !ok || !agentsuite.DescriptorSizeAndDigestMatch(instructions, member.Instructions.Descriptor) {
		return MemberMaterial{}, ErrMemberMaterial
	}
	if err := ctx.Err(); err != nil {
		return MemberMaterial{}, err
	}
	member.Model = cloneModelRequirement(member.Model)
	member.Instructions.Descriptor = cloneDescriptor(member.Instructions.Descriptor)
	return MemberMaterial{
		ArtifactDigest:         artifactDigest,
		GraphDigest:            graphDigest,
		SuiteName:              suite.Name,
		MemberID:               member.ID,
		MemberDescriptor:       cloneDescriptor(ref.Descriptor),
		Description:            member.Description,
		Instructions:           bytes.Clone(instructions),
		InstructionsDescriptor: cloneDescriptor(member.Instructions.Descriptor),
		Model:                  cloneModelRequirement(member.Model),
		Agent:                  member,
	}, nil
}

func cloneDescriptor(value agentsuite.Descriptor) agentsuite.Descriptor {
	if value.Annotations != nil {
		annotations := make(map[string]string, len(value.Annotations))
		for key, item := range value.Annotations {
			annotations[key] = item
		}
		value.Annotations = annotations
	}
	return value
}

func cloneModelRequirement(value agentsuite.ModelRequirement) agentsuite.ModelRequirement {
	if value.Capabilities != nil {
		capabilities := *value.Capabilities
		value.Capabilities = &capabilities
	}
	value.SecretRefs = append([]string(nil), value.SecretRefs...)
	return value
}
