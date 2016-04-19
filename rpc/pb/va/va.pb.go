// Code generated by protoc-gen-go.
// source: va/va.proto
// DO NOT EDIT!

/*
Package va is a generated protocol buffer package.

It is generated from these files:
	va/va.proto

It has these top-level messages:
	Domain
	Valid
	PerformValidationRequest
	VAChallenge
	AuthzMeta
	ValidationRecords
	ValidationRecord
*/
package va

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import core "github.com/letsencrypt/boulder/rpc/pb/core"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
const _ = proto.ProtoPackageIsVersion1

type Domain struct {
	Domain           *string `protobuf:"bytes,1,opt,name=domain" json:"domain,omitempty"`
	XXX_unrecognized []byte  `json:"-"`
}

func (m *Domain) Reset()                    { *m = Domain{} }
func (m *Domain) String() string            { return proto.CompactTextString(m) }
func (*Domain) ProtoMessage()               {}
func (*Domain) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *Domain) GetDomain() string {
	if m != nil && m.Domain != nil {
		return *m.Domain
	}
	return ""
}

type Valid struct {
	Valid            *bool  `protobuf:"varint,1,opt,name=valid" json:"valid,omitempty"`
	XXX_unrecognized []byte `json:"-"`
}

func (m *Valid) Reset()                    { *m = Valid{} }
func (m *Valid) String() string            { return proto.CompactTextString(m) }
func (*Valid) ProtoMessage()               {}
func (*Valid) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *Valid) GetValid() bool {
	if m != nil && m.Valid != nil {
		return *m.Valid
	}
	return false
}

type PerformValidationRequest struct {
	Domain           *string      `protobuf:"bytes,1,opt,name=domain" json:"domain,omitempty"`
	Challenge        *VAChallenge `protobuf:"bytes,2,opt,name=challenge" json:"challenge,omitempty"`
	Authz            *AuthzMeta   `protobuf:"bytes,3,opt,name=authz" json:"authz,omitempty"`
	XXX_unrecognized []byte       `json:"-"`
}

func (m *PerformValidationRequest) Reset()                    { *m = PerformValidationRequest{} }
func (m *PerformValidationRequest) String() string            { return proto.CompactTextString(m) }
func (*PerformValidationRequest) ProtoMessage()               {}
func (*PerformValidationRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *PerformValidationRequest) GetDomain() string {
	if m != nil && m.Domain != nil {
		return *m.Domain
	}
	return ""
}

func (m *PerformValidationRequest) GetChallenge() *VAChallenge {
	if m != nil {
		return m.Challenge
	}
	return nil
}

func (m *PerformValidationRequest) GetAuthz() *AuthzMeta {
	if m != nil {
		return m.Authz
	}
	return nil
}

// VAChallenge contains just the fields of core.Challenge that the VA needs
type VAChallenge struct {
	Id               *int64  `protobuf:"varint,1,opt,name=id" json:"id,omitempty"`
	Type             *string `protobuf:"bytes,2,opt,name=type" json:"type,omitempty"`
	Status           *string `protobuf:"bytes,6,opt,name=status" json:"status,omitempty"`
	Token            *string `protobuf:"bytes,3,opt,name=token" json:"token,omitempty"`
	AccountKey       *string `protobuf:"bytes,4,opt,name=accountKey" json:"accountKey,omitempty"`
	KeyAuthorization *string `protobuf:"bytes,5,opt,name=keyAuthorization" json:"keyAuthorization,omitempty"`
	XXX_unrecognized []byte  `json:"-"`
}

func (m *VAChallenge) Reset()                    { *m = VAChallenge{} }
func (m *VAChallenge) String() string            { return proto.CompactTextString(m) }
func (*VAChallenge) ProtoMessage()               {}
func (*VAChallenge) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *VAChallenge) GetId() int64 {
	if m != nil && m.Id != nil {
		return *m.Id
	}
	return 0
}

func (m *VAChallenge) GetType() string {
	if m != nil && m.Type != nil {
		return *m.Type
	}
	return ""
}

func (m *VAChallenge) GetStatus() string {
	if m != nil && m.Status != nil {
		return *m.Status
	}
	return ""
}

func (m *VAChallenge) GetToken() string {
	if m != nil && m.Token != nil {
		return *m.Token
	}
	return ""
}

func (m *VAChallenge) GetAccountKey() string {
	if m != nil && m.AccountKey != nil {
		return *m.AccountKey
	}
	return ""
}

func (m *VAChallenge) GetKeyAuthorization() string {
	if m != nil && m.KeyAuthorization != nil {
		return *m.KeyAuthorization
	}
	return ""
}

type AuthzMeta struct {
	Id               *string `protobuf:"bytes,1,opt,name=id" json:"id,omitempty"`
	RegID            *int64  `protobuf:"varint,2,opt,name=regID" json:"regID,omitempty"`
	XXX_unrecognized []byte  `json:"-"`
}

func (m *AuthzMeta) Reset()                    { *m = AuthzMeta{} }
func (m *AuthzMeta) String() string            { return proto.CompactTextString(m) }
func (*AuthzMeta) ProtoMessage()               {}
func (*AuthzMeta) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

func (m *AuthzMeta) GetId() string {
	if m != nil && m.Id != nil {
		return *m.Id
	}
	return ""
}

func (m *AuthzMeta) GetRegID() int64 {
	if m != nil && m.RegID != nil {
		return *m.RegID
	}
	return 0
}

type ValidationRecords struct {
	Records          []*ValidationRecord  `protobuf:"bytes,1,rep,name=records" json:"records,omitempty"`
	Problems         *core.ProblemDetails `protobuf:"bytes,2,opt,name=problems" json:"problems,omitempty"`
	XXX_unrecognized []byte               `json:"-"`
}

func (m *ValidationRecords) Reset()                    { *m = ValidationRecords{} }
func (m *ValidationRecords) String() string            { return proto.CompactTextString(m) }
func (*ValidationRecords) ProtoMessage()               {}
func (*ValidationRecords) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{5} }

func (m *ValidationRecords) GetRecords() []*ValidationRecord {
	if m != nil {
		return m.Records
	}
	return nil
}

func (m *ValidationRecords) GetProblems() *core.ProblemDetails {
	if m != nil {
		return m.Problems
	}
	return nil
}

type ValidationRecord struct {
	Hostname          *string  `protobuf:"bytes,1,opt,name=hostname" json:"hostname,omitempty"`
	Port              *string  `protobuf:"bytes,2,opt,name=port" json:"port,omitempty"`
	AddressesResolved []string `protobuf:"bytes,3,rep,name=addressesResolved" json:"addressesResolved,omitempty"`
	AddressUsed       *string  `protobuf:"bytes,4,opt,name=addressUsed" json:"addressUsed,omitempty"`
	Authorities       []string `protobuf:"bytes,5,rep,name=authorities" json:"authorities,omitempty"`
	Url               *string  `protobuf:"bytes,6,opt,name=url" json:"url,omitempty"`
	XXX_unrecognized  []byte   `json:"-"`
}

func (m *ValidationRecord) Reset()                    { *m = ValidationRecord{} }
func (m *ValidationRecord) String() string            { return proto.CompactTextString(m) }
func (*ValidationRecord) ProtoMessage()               {}
func (*ValidationRecord) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{6} }

func (m *ValidationRecord) GetHostname() string {
	if m != nil && m.Hostname != nil {
		return *m.Hostname
	}
	return ""
}

func (m *ValidationRecord) GetPort() string {
	if m != nil && m.Port != nil {
		return *m.Port
	}
	return ""
}

func (m *ValidationRecord) GetAddressesResolved() []string {
	if m != nil {
		return m.AddressesResolved
	}
	return nil
}

func (m *ValidationRecord) GetAddressUsed() string {
	if m != nil && m.AddressUsed != nil {
		return *m.AddressUsed
	}
	return ""
}

func (m *ValidationRecord) GetAuthorities() []string {
	if m != nil {
		return m.Authorities
	}
	return nil
}

func (m *ValidationRecord) GetUrl() string {
	if m != nil && m.Url != nil {
		return *m.Url
	}
	return ""
}

func init() {
	proto.RegisterType((*Domain)(nil), "va.Domain")
	proto.RegisterType((*Valid)(nil), "va.Valid")
	proto.RegisterType((*PerformValidationRequest)(nil), "va.PerformValidationRequest")
	proto.RegisterType((*VAChallenge)(nil), "va.VAChallenge")
	proto.RegisterType((*AuthzMeta)(nil), "va.AuthzMeta")
	proto.RegisterType((*ValidationRecords)(nil), "va.ValidationRecords")
	proto.RegisterType((*ValidationRecord)(nil), "va.ValidationRecord")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion1

// Client API for VA service

type VAClient interface {
	IsSafeDomain(ctx context.Context, in *Domain, opts ...grpc.CallOption) (*Valid, error)
	PerformValidation(ctx context.Context, in *PerformValidationRequest, opts ...grpc.CallOption) (*ValidationRecords, error)
}

type vAClient struct {
	cc *grpc.ClientConn
}

func NewVAClient(cc *grpc.ClientConn) VAClient {
	return &vAClient{cc}
}

func (c *vAClient) IsSafeDomain(ctx context.Context, in *Domain, opts ...grpc.CallOption) (*Valid, error) {
	out := new(Valid)
	err := grpc.Invoke(ctx, "/va.VA/IsSafeDomain", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *vAClient) PerformValidation(ctx context.Context, in *PerformValidationRequest, opts ...grpc.CallOption) (*ValidationRecords, error) {
	out := new(ValidationRecords)
	err := grpc.Invoke(ctx, "/va.VA/PerformValidation", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for VA service

type VAServer interface {
	IsSafeDomain(context.Context, *Domain) (*Valid, error)
	PerformValidation(context.Context, *PerformValidationRequest) (*ValidationRecords, error)
}

func RegisterVAServer(s *grpc.Server, srv VAServer) {
	s.RegisterService(&_VA_serviceDesc, srv)
}

func _VA_IsSafeDomain_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error) (interface{}, error) {
	in := new(Domain)
	if err := dec(in); err != nil {
		return nil, err
	}
	out, err := srv.(VAServer).IsSafeDomain(ctx, in)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func _VA_PerformValidation_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error) (interface{}, error) {
	in := new(PerformValidationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	out, err := srv.(VAServer).PerformValidation(ctx, in)
	if err != nil {
		return nil, err
	}
	return out, nil
}

var _VA_serviceDesc = grpc.ServiceDesc{
	ServiceName: "va.VA",
	HandlerType: (*VAServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "IsSafeDomain",
			Handler:    _VA_IsSafeDomain_Handler,
		},
		{
			MethodName: "PerformValidation",
			Handler:    _VA_PerformValidation_Handler,
		},
	},
	Streams: []grpc.StreamDesc{},
}

var fileDescriptor0 = []byte{
	// 475 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0x74, 0x52, 0x6d, 0x6e, 0xd3, 0x40,
	0x10, 0xad, 0xe3, 0xa6, 0xc4, 0x13, 0xa0, 0xc9, 0x28, 0x20, 0x2b, 0x02, 0x14, 0x2d, 0x3f, 0x40,
	0x08, 0x52, 0xe8, 0x0d, 0x22, 0xf2, 0xa7, 0x20, 0xa4, 0x6a, 0x11, 0xf9, 0xbf, 0xc4, 0xd3, 0xc6,
	0xaa, 0xe3, 0x0d, 0xbb, 0x6b, 0x4b, 0xe9, 0x01, 0xb8, 0x0c, 0xf7, 0xe0, 0x5c, 0xec, 0x87, 0x93,
	0x5a, 0x0d, 0xfd, 0x63, 0xbd, 0x79, 0xf3, 0xbc, 0xfb, 0xf6, 0xcd, 0x40, 0xbf, 0x16, 0x67, 0xb5,
	0x98, 0x6e, 0x94, 0x34, 0x12, 0x3b, 0xb5, 0x18, 0x9f, 0x2e, 0xa5, 0xa2, 0x33, 0xf7, 0x09, 0x24,
	0x9b, 0xc0, 0xc9, 0x5c, 0xae, 0x45, 0x5e, 0xe2, 0x73, 0x38, 0xc9, 0x3c, 0x4a, 0xa3, 0x49, 0xf4,
	0x36, 0xe1, 0x4d, 0xc5, 0x5e, 0x42, 0x77, 0x21, 0x8a, 0x3c, 0xc3, 0x11, 0x74, 0x6b, 0x07, 0x7c,
	0xbf, 0xc7, 0x43, 0xc1, 0x7e, 0x47, 0x90, 0x5e, 0x92, 0xba, 0x92, 0x6a, 0xed, 0x65, 0xc2, 0xe4,
	0xb2, 0xe4, 0xf4, 0xab, 0x22, 0x6d, 0x1e, 0x3a, 0x13, 0x3f, 0x40, 0xb2, 0x5c, 0x89, 0xa2, 0xa0,
	0xf2, 0x9a, 0xd2, 0x8e, 0x6d, 0xf5, 0xcf, 0x4f, 0xa7, 0xd6, 0xe8, 0x62, 0xf6, 0x79, 0x47, 0xf3,
	0x3b, 0x05, 0xbe, 0x86, 0xae, 0xa8, 0xcc, 0xea, 0x36, 0x8d, 0xbd, 0xf4, 0x89, 0x93, 0xce, 0x1c,
	0xf1, 0x8d, 0x8c, 0xe0, 0xa1, 0xc7, 0xfe, 0x44, 0xd0, 0x6f, 0xfd, 0x8f, 0x4f, 0xa1, 0xd3, 0x78,
	0x8d, 0xb9, 0x45, 0x88, 0x70, 0x6c, 0xb6, 0x9b, 0x70, 0x5d, 0xc2, 0x3d, 0x76, 0xfe, 0xb4, 0x11,
	0xa6, 0xd2, 0xe9, 0x49, 0xf0, 0x17, 0x2a, 0xf7, 0x54, 0x23, 0x6f, 0xa8, 0xf4, 0x17, 0x26, 0x3c,
	0x14, 0xf8, 0x0a, 0x40, 0x2c, 0x97, 0xb2, 0x2a, 0xcd, 0x57, 0xda, 0xa6, 0xc7, 0xbe, 0xd5, 0x62,
	0xf0, 0x1d, 0x0c, 0x6e, 0x68, 0xeb, 0x8c, 0x49, 0x95, 0xdf, 0xfa, 0x20, 0xd2, 0xae, 0x57, 0x1d,
	0xf0, 0xec, 0x13, 0x24, 0xfb, 0x17, 0xb4, 0xac, 0x26, 0xde, 0xaa, 0xbd, 0x5e, 0xd1, 0xf5, 0xc5,
	0xdc, 0x7b, 0x8d, 0x79, 0x28, 0x58, 0x05, 0xc3, 0x76, 0xc2, 0x76, 0x88, 0x99, 0xc6, 0x29, 0x3c,
	0x52, 0x01, 0xda, 0xff, 0x63, 0x1b, 0xce, 0xc8, 0xe7, 0x78, 0x4f, 0xc7, 0x77, 0x22, 0xfc, 0x08,
	0x3d, 0x3b, 0xf8, 0x9f, 0x05, 0xad, 0x75, 0x13, 0xfc, 0x68, 0xea, 0xd7, 0xe1, 0x32, 0xb0, 0x73,
	0xeb, 0x27, 0x2f, 0x34, 0xdf, 0xab, 0xd8, 0xdf, 0x08, 0x06, 0xf7, 0xcf, 0xc3, 0x31, 0xf4, 0x56,
	0x52, 0x9b, 0x52, 0xac, 0xa9, 0xf1, 0xbd, 0xaf, 0x5d, 0xd0, 0x1b, 0xa9, 0xcc, 0x2e, 0x68, 0x87,
	0xf1, 0x3d, 0x0c, 0x45, 0x96, 0x29, 0xd2, 0x9a, 0x34, 0x27, 0x2d, 0x8b, 0x9a, 0x32, 0x1b, 0x6e,
	0x6c, 0x05, 0x87, 0x0d, 0x9c, 0x40, 0xbf, 0x21, 0x7f, 0x68, 0xab, 0x0b, 0x49, 0xb7, 0x29, 0xaf,
	0x08, 0x79, 0x9a, 0x9c, 0xb4, 0x4d, 0x39, 0xf6, 0x8a, 0x3b, 0x0a, 0x07, 0x10, 0x57, 0xaa, 0x68,
	0xe6, 0xea, 0xe0, 0xf9, 0x16, 0x3a, 0x8b, 0x19, 0xbe, 0x81, 0xc7, 0x17, 0xfa, 0xbb, 0xb8, 0xa2,
	0x66, 0xed, 0xc1, 0xe5, 0x15, 0xf0, 0x38, 0xd9, 0x67, 0xc7, 0x8e, 0xf0, 0x0b, 0x0c, 0x0f, 0xf6,
	0x1a, 0x5f, 0x38, 0xc5, 0x43, 0xeb, 0x3e, 0x7e, 0xf6, 0xbf, 0xec, 0x35, 0x3b, 0xfa, 0x17, 0x00,
	0x00, 0xff, 0xff, 0x6a, 0x2a, 0x2d, 0x61, 0x88, 0x03, 0x00, 0x00,
}
