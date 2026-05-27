package internal

import (
	"fmt"

	"github.com/GoCodeAlone/workflow-plugin-auth0/internal/contracts"
	pb "github.com/GoCodeAlone/workflow/plugin/external/proto"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

var Version = "0.0.0"

type auth0Plugin struct{}

func NewAuth0Plugin() sdk.PluginProvider {
	return &auth0Plugin{}
}

func (p *auth0Plugin) Manifest() sdk.PluginManifest {
	return sdk.PluginManifest{
		Name:        "workflow-plugin-auth0",
		Version:     Version,
		Author:      "GoCodeAlone",
		Description: "Auth0 management provider plugin backed by the official Auth0 Go SDK",
	}
}

func (p *auth0Plugin) ModuleTypes() []string {
	return []string{"auth0.provider"}
}

func (p *auth0Plugin) TypedModuleTypes() []string {
	return p.ModuleTypes()
}

func (p *auth0Plugin) CreateModule(typeName, name string, config map[string]any) (sdk.ModuleInstance, error) {
	switch typeName {
	case "auth0.provider":
		return newAuth0Module(name, config)
	default:
		return nil, fmt.Errorf("auth0 plugin: unknown module type %q", typeName)
	}
}

func (p *auth0Plugin) CreateTypedModule(typeName, name string, config *anypb.Any) (sdk.ModuleInstance, error) {
	if typeName != "auth0.provider" {
		return nil, fmt.Errorf("auth0 plugin: unknown typed module type %q", typeName)
	}
	factory := sdk.NewTypedModuleFactory(typeName, &contracts.ProviderConfig{}, func(name string, cfg *contracts.ProviderConfig) (sdk.ModuleInstance, error) {
		return newAuth0Module(name, typedModuleConfig(cfg))
	})
	return factory.CreateTypedModule(typeName, name, config)
}

func (p *auth0Plugin) StepTypes() []string {
	return allStepTypes()
}

func (p *auth0Plugin) TypedStepTypes() []string {
	return p.StepTypes()
}

func (p *auth0Plugin) CreateStep(typeName, name string, config map[string]any) (sdk.StepInstance, error) {
	return createStep(typeName, name, config)
}

func (p *auth0Plugin) CreateTypedStep(typeName, name string, config *anypb.Any) (sdk.StepInstance, error) {
	if _, ok := stepRegistry[typeName]; !ok {
		return nil, fmt.Errorf("%w: step type %q", sdk.ErrTypedContractNotHandled, typeName)
	}
	if typeName == "step.auth0_auth_provider_describe" {
		return sdk.NewTypedStepFactory(typeName, &contracts.AuthProviderDescribeConfig{}, &contracts.AuthProviderDescribeInput{}, typedAuthProviderDescribe).CreateTypedStep(typeName, name, config)
	}
	return sdk.NewTypedStepFactory(typeName, &contracts.Auth0StepConfig{}, &contracts.Auth0StepInput{}, typedStepHandler(typeName)).CreateTypedStep(typeName, name, config)
}

func (p *auth0Plugin) ContractRegistry() *pb.ContractRegistry {
	return contractRegistry
}

var contractRegistry = &pb.ContractRegistry{
	FileDescriptorSet: &descriptorpb.FileDescriptorSet{
		File: []*descriptorpb.FileDescriptorProto{
			protodesc.ToFileDescriptorProto(structpb.File_google_protobuf_struct_proto),
			protodesc.ToFileDescriptorProto(contracts.File_internal_contracts_auth0_proto),
		},
	},
	Contracts: contractDescriptors(),
}

func contractDescriptors() []*pb.ContractDescriptor {
	descriptors := []*pb.ContractDescriptor{
		moduleContract("auth0.provider", "ProviderConfig"),
	}
	for _, stepType := range allStepTypes() {
		if stepType == "step.auth0_auth_provider_describe" {
			descriptors = append(descriptors, stepContract(stepType, "AuthProviderDescribeConfig", "AuthProviderDescribeInput", "AuthProviderDescribeOutput"))
			continue
		}
		descriptors = append(descriptors, stepContract(stepType, "Auth0StepConfig", "Auth0StepInput", "Auth0StepOutput"))
	}
	return descriptors
}

func moduleContract(moduleType, configMessage string) *pb.ContractDescriptor {
	const pkg = "workflow.plugins.auth0.v1."
	return &pb.ContractDescriptor{
		Kind:          pb.ContractKind_CONTRACT_KIND_MODULE,
		ModuleType:    moduleType,
		ConfigMessage: pkg + configMessage,
		Mode:          pb.ContractMode_CONTRACT_MODE_STRICT_PROTO,
	}
}

func stepContract(stepType, configMessage, inputMessage, outputMessage string) *pb.ContractDescriptor {
	const pkg = "workflow.plugins.auth0.v1."
	return &pb.ContractDescriptor{
		Kind:          pb.ContractKind_CONTRACT_KIND_STEP,
		StepType:      stepType,
		ConfigMessage: pkg + configMessage,
		InputMessage:  pkg + inputMessage,
		OutputMessage: pkg + outputMessage,
		Mode:          pb.ContractMode_CONTRACT_MODE_STRICT_PROTO,
	}
}
