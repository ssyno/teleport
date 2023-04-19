// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        (unknown)
// source: teleport/assistant/v1/assistant.proto

package v1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// ChatCompletionMessage is a message in the OpenAI format.
type ChatCompletionMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Role    string `protobuf:"bytes,1,opt,name=role,proto3" json:"role,omitempty"`
	Content string `protobuf:"bytes,2,opt,name=content,proto3" json:"content,omitempty"`
	Name    string `protobuf:"bytes,3,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *ChatCompletionMessage) Reset() {
	*x = ChatCompletionMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_assistant_v1_assistant_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ChatCompletionMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ChatCompletionMessage) ProtoMessage() {}

func (x *ChatCompletionMessage) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_assistant_v1_assistant_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ChatCompletionMessage.ProtoReflect.Descriptor instead.
func (*ChatCompletionMessage) Descriptor() ([]byte, []int) {
	return file_teleport_assistant_v1_assistant_proto_rawDescGZIP(), []int{0}
}

func (x *ChatCompletionMessage) GetRole() string {
	if x != nil {
		return x.Role
	}
	return ""
}

func (x *ChatCompletionMessage) GetContent() string {
	if x != nil {
		return x.Content
	}
	return ""
}

func (x *ChatCompletionMessage) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

// CompletionRequest is a request
type CompleteRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Username string                   `protobuf:"bytes,1,opt,name=username,proto3" json:"username,omitempty"`
	Messages []*ChatCompletionMessage `protobuf:"bytes,2,rep,name=messages,proto3" json:"messages,omitempty"`
}

func (x *CompleteRequest) Reset() {
	*x = CompleteRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_assistant_v1_assistant_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CompleteRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CompleteRequest) ProtoMessage() {}

func (x *CompleteRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_assistant_v1_assistant_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CompleteRequest.ProtoReflect.Descriptor instead.
func (*CompleteRequest) Descriptor() ([]byte, []int) {
	return file_teleport_assistant_v1_assistant_proto_rawDescGZIP(), []int{1}
}

func (x *CompleteRequest) GetUsername() string {
	if x != nil {
		return x.Username
	}
	return ""
}

func (x *CompleteRequest) GetMessages() []*ChatCompletionMessage {
	if x != nil {
		return x.Messages
	}
	return nil
}

// Label are Teleport resource labels.
type Label struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Key   string `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	Value string `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
}

func (x *Label) Reset() {
	*x = Label{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_assistant_v1_assistant_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Label) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Label) ProtoMessage() {}

func (x *Label) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_assistant_v1_assistant_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Label.ProtoReflect.Descriptor instead.
func (*Label) Descriptor() ([]byte, []int) {
	return file_teleport_assistant_v1_assistant_proto_rawDescGZIP(), []int{2}
}

func (x *Label) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *Label) GetValue() string {
	if x != nil {
		return x.Value
	}
	return ""
}

// CompletionResponse is a response in Complete method.
type CompletionResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Kind    string   `protobuf:"bytes,1,opt,name=kind,proto3" json:"kind,omitempty"`
	Content string   `protobuf:"bytes,2,opt,name=content,proto3" json:"content,omitempty"`
	Command string   `protobuf:"bytes,3,opt,name=command,proto3" json:"command,omitempty"` // Command should be probably replaced by oneof in the future to support more commands.
	Nodes   []string `protobuf:"bytes,4,rep,name=nodes,proto3" json:"nodes,omitempty"`
	Labels  []*Label `protobuf:"bytes,5,rep,name=labels,proto3" json:"labels,omitempty"`
}

func (x *CompletionResponse) Reset() {
	*x = CompletionResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_assistant_v1_assistant_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CompletionResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CompletionResponse) ProtoMessage() {}

func (x *CompletionResponse) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_assistant_v1_assistant_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CompletionResponse.ProtoReflect.Descriptor instead.
func (*CompletionResponse) Descriptor() ([]byte, []int) {
	return file_teleport_assistant_v1_assistant_proto_rawDescGZIP(), []int{3}
}

func (x *CompletionResponse) GetKind() string {
	if x != nil {
		return x.Kind
	}
	return ""
}

func (x *CompletionResponse) GetContent() string {
	if x != nil {
		return x.Content
	}
	return ""
}

func (x *CompletionResponse) GetCommand() string {
	if x != nil {
		return x.Command
	}
	return ""
}

func (x *CompletionResponse) GetNodes() []string {
	if x != nil {
		return x.Nodes
	}
	return nil
}

func (x *CompletionResponse) GetLabels() []*Label {
	if x != nil {
		return x.Labels
	}
	return nil
}

var File_teleport_assistant_v1_assistant_proto protoreflect.FileDescriptor

var file_teleport_assistant_v1_assistant_proto_rawDesc = []byte{
	0x0a, 0x25, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x61, 0x73, 0x73, 0x69, 0x73,
	0x74, 0x61, 0x6e, 0x74, 0x2f, 0x76, 0x31, 0x2f, 0x61, 0x73, 0x73, 0x69, 0x73, 0x74, 0x61, 0x6e,
	0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x15, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72,
	0x74, 0x2e, 0x61, 0x73, 0x73, 0x69, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x2e, 0x76, 0x31, 0x22, 0x59,
	0x0a, 0x15, 0x43, 0x68, 0x61, 0x74, 0x43, 0x6f, 0x6d, 0x70, 0x6c, 0x65, 0x74, 0x69, 0x6f, 0x6e,
	0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x72, 0x6f, 0x6c, 0x65, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x72, 0x6f, 0x6c, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x63,
	0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x63, 0x6f,
	0x6e, 0x74, 0x65, 0x6e, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0x77, 0x0a, 0x0f, 0x43, 0x6f, 0x6d,
	0x70, 0x6c, 0x65, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1a, 0x0a, 0x08,
	0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08,
	0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x48, 0x0a, 0x08, 0x6d, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x2c, 0x2e, 0x74, 0x65, 0x6c,
	0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x61, 0x73, 0x73, 0x69, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x2e,
	0x76, 0x31, 0x2e, 0x43, 0x68, 0x61, 0x74, 0x43, 0x6f, 0x6d, 0x70, 0x6c, 0x65, 0x74, 0x69, 0x6f,
	0x6e, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x52, 0x08, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67,
	0x65, 0x73, 0x22, 0x2f, 0x0a, 0x05, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x12, 0x10, 0x0a, 0x03, 0x6b,
	0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a,
	0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61,
	0x6c, 0x75, 0x65, 0x22, 0xa8, 0x01, 0x0a, 0x12, 0x43, 0x6f, 0x6d, 0x70, 0x6c, 0x65, 0x74, 0x69,
	0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x6b, 0x69,
	0x6e, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6b, 0x69, 0x6e, 0x64, 0x12, 0x18,
	0x0a, 0x07, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x07, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x63, 0x6f, 0x6d, 0x6d,
	0x61, 0x6e, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x63, 0x6f, 0x6d, 0x6d, 0x61,
	0x6e, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x6e, 0x6f, 0x64, 0x65, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28,
	0x09, 0x52, 0x05, 0x6e, 0x6f, 0x64, 0x65, 0x73, 0x12, 0x34, 0x0a, 0x06, 0x6c, 0x61, 0x62, 0x65,
	0x6c, 0x73, 0x18, 0x05, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70,
	0x6f, 0x72, 0x74, 0x2e, 0x61, 0x73, 0x73, 0x69, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x2e, 0x76, 0x31,
	0x2e, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x52, 0x06, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x32, 0x71,
	0x0a, 0x10, 0x41, 0x73, 0x73, 0x69, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x53, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x12, 0x5d, 0x0a, 0x08, 0x43, 0x6f, 0x6d, 0x70, 0x6c, 0x65, 0x74, 0x65, 0x12, 0x26,
	0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x61, 0x73, 0x73, 0x69, 0x73, 0x74,
	0x61, 0x6e, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x6f, 0x6d, 0x70, 0x6c, 0x65, 0x74, 0x65, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x29, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72,
	0x74, 0x2e, 0x61, 0x73, 0x73, 0x69, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x43,
	0x6f, 0x6d, 0x70, 0x6c, 0x65, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x42, 0x41, 0x5a, 0x3f, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
	0x67, 0x72, 0x61, 0x76, 0x69, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x2f, 0x74, 0x65,
	0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x2f, 0x61, 0x73, 0x73, 0x69, 0x73, 0x74, 0x61, 0x6e,
	0x74, 0x2f, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_teleport_assistant_v1_assistant_proto_rawDescOnce sync.Once
	file_teleport_assistant_v1_assistant_proto_rawDescData = file_teleport_assistant_v1_assistant_proto_rawDesc
)

func file_teleport_assistant_v1_assistant_proto_rawDescGZIP() []byte {
	file_teleport_assistant_v1_assistant_proto_rawDescOnce.Do(func() {
		file_teleport_assistant_v1_assistant_proto_rawDescData = protoimpl.X.CompressGZIP(file_teleport_assistant_v1_assistant_proto_rawDescData)
	})
	return file_teleport_assistant_v1_assistant_proto_rawDescData
}

var file_teleport_assistant_v1_assistant_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_teleport_assistant_v1_assistant_proto_goTypes = []interface{}{
	(*ChatCompletionMessage)(nil), // 0: teleport.assistant.v1.ChatCompletionMessage
	(*CompleteRequest)(nil),       // 1: teleport.assistant.v1.CompleteRequest
	(*Label)(nil),                 // 2: teleport.assistant.v1.Label
	(*CompletionResponse)(nil),    // 3: teleport.assistant.v1.CompletionResponse
}
var file_teleport_assistant_v1_assistant_proto_depIdxs = []int32{
	0, // 0: teleport.assistant.v1.CompleteRequest.messages:type_name -> teleport.assistant.v1.ChatCompletionMessage
	2, // 1: teleport.assistant.v1.CompletionResponse.labels:type_name -> teleport.assistant.v1.Label
	1, // 2: teleport.assistant.v1.AssistantService.Complete:input_type -> teleport.assistant.v1.CompleteRequest
	3, // 3: teleport.assistant.v1.AssistantService.Complete:output_type -> teleport.assistant.v1.CompletionResponse
	3, // [3:4] is the sub-list for method output_type
	2, // [2:3] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_teleport_assistant_v1_assistant_proto_init() }
func file_teleport_assistant_v1_assistant_proto_init() {
	if File_teleport_assistant_v1_assistant_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_teleport_assistant_v1_assistant_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ChatCompletionMessage); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_teleport_assistant_v1_assistant_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CompleteRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_teleport_assistant_v1_assistant_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Label); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_teleport_assistant_v1_assistant_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CompletionResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_teleport_assistant_v1_assistant_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_teleport_assistant_v1_assistant_proto_goTypes,
		DependencyIndexes: file_teleport_assistant_v1_assistant_proto_depIdxs,
		MessageInfos:      file_teleport_assistant_v1_assistant_proto_msgTypes,
	}.Build()
	File_teleport_assistant_v1_assistant_proto = out.File
	file_teleport_assistant_v1_assistant_proto_rawDesc = nil
	file_teleport_assistant_v1_assistant_proto_goTypes = nil
	file_teleport_assistant_v1_assistant_proto_depIdxs = nil
}
