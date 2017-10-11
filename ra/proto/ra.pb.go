// Code generated by protoc-gen-go.
// source: ra/proto/ra.proto
// DO NOT EDIT!

/*
Package proto is a generated protocol buffer package.

It is generated from these files:
	ra/proto/ra.proto

It has these top-level messages:
	NewAuthorizationRequest
	NewCertificateRequest
	UpdateRegistrationRequest
	UpdateAuthorizationRequest
	RevokeCertificateWithRegRequest
	AdministrativelyRevokeCertificateRequest
	NewOrderRequest
	FinalizeOrderRequest
*/
package proto

import proto1 "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import core "github.com/letsencrypt/boulder/core/proto"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto1.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto1.ProtoPackageIsVersion2 // please upgrade the proto package

type NewAuthorizationRequest struct {
	Authz            *core.Authorization `protobuf:"bytes,1,opt,name=authz" json:"authz,omitempty"`
	RegID            *int64              `protobuf:"varint,2,opt,name=regID" json:"regID,omitempty"`
	XXX_unrecognized []byte              `json:"-"`
}

func (m *NewAuthorizationRequest) Reset()                    { *m = NewAuthorizationRequest{} }
func (m *NewAuthorizationRequest) String() string            { return proto1.CompactTextString(m) }
func (*NewAuthorizationRequest) ProtoMessage()               {}
func (*NewAuthorizationRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *NewAuthorizationRequest) GetAuthz() *core.Authorization {
	if m != nil {
		return m.Authz
	}
	return nil
}

func (m *NewAuthorizationRequest) GetRegID() int64 {
	if m != nil && m.RegID != nil {
		return *m.RegID
	}
	return 0
}

type NewCertificateRequest struct {
	Csr              []byte `protobuf:"bytes,1,opt,name=csr" json:"csr,omitempty"`
	RegID            *int64 `protobuf:"varint,2,opt,name=regID" json:"regID,omitempty"`
	XXX_unrecognized []byte `json:"-"`
}

func (m *NewCertificateRequest) Reset()                    { *m = NewCertificateRequest{} }
func (m *NewCertificateRequest) String() string            { return proto1.CompactTextString(m) }
func (*NewCertificateRequest) ProtoMessage()               {}
func (*NewCertificateRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *NewCertificateRequest) GetCsr() []byte {
	if m != nil {
		return m.Csr
	}
	return nil
}

func (m *NewCertificateRequest) GetRegID() int64 {
	if m != nil && m.RegID != nil {
		return *m.RegID
	}
	return 0
}

type UpdateRegistrationRequest struct {
	Base             *core.Registration `protobuf:"bytes,1,opt,name=base" json:"base,omitempty"`
	Update           *core.Registration `protobuf:"bytes,2,opt,name=update" json:"update,omitempty"`
	XXX_unrecognized []byte             `json:"-"`
}

func (m *UpdateRegistrationRequest) Reset()                    { *m = UpdateRegistrationRequest{} }
func (m *UpdateRegistrationRequest) String() string            { return proto1.CompactTextString(m) }
func (*UpdateRegistrationRequest) ProtoMessage()               {}
func (*UpdateRegistrationRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *UpdateRegistrationRequest) GetBase() *core.Registration {
	if m != nil {
		return m.Base
	}
	return nil
}

func (m *UpdateRegistrationRequest) GetUpdate() *core.Registration {
	if m != nil {
		return m.Update
	}
	return nil
}

type UpdateAuthorizationRequest struct {
	Authz            *core.Authorization `protobuf:"bytes,1,opt,name=authz" json:"authz,omitempty"`
	ChallengeIndex   *int64              `protobuf:"varint,2,opt,name=challengeIndex" json:"challengeIndex,omitempty"`
	Response         *core.Challenge     `protobuf:"bytes,3,opt,name=response" json:"response,omitempty"`
	XXX_unrecognized []byte              `json:"-"`
}

func (m *UpdateAuthorizationRequest) Reset()                    { *m = UpdateAuthorizationRequest{} }
func (m *UpdateAuthorizationRequest) String() string            { return proto1.CompactTextString(m) }
func (*UpdateAuthorizationRequest) ProtoMessage()               {}
func (*UpdateAuthorizationRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *UpdateAuthorizationRequest) GetAuthz() *core.Authorization {
	if m != nil {
		return m.Authz
	}
	return nil
}

func (m *UpdateAuthorizationRequest) GetChallengeIndex() int64 {
	if m != nil && m.ChallengeIndex != nil {
		return *m.ChallengeIndex
	}
	return 0
}

func (m *UpdateAuthorizationRequest) GetResponse() *core.Challenge {
	if m != nil {
		return m.Response
	}
	return nil
}

type RevokeCertificateWithRegRequest struct {
	Cert             []byte `protobuf:"bytes,1,opt,name=cert" json:"cert,omitempty"`
	Code             *int64 `protobuf:"varint,2,opt,name=code" json:"code,omitempty"`
	RegID            *int64 `protobuf:"varint,3,opt,name=regID" json:"regID,omitempty"`
	XXX_unrecognized []byte `json:"-"`
}

func (m *RevokeCertificateWithRegRequest) Reset()                    { *m = RevokeCertificateWithRegRequest{} }
func (m *RevokeCertificateWithRegRequest) String() string            { return proto1.CompactTextString(m) }
func (*RevokeCertificateWithRegRequest) ProtoMessage()               {}
func (*RevokeCertificateWithRegRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

func (m *RevokeCertificateWithRegRequest) GetCert() []byte {
	if m != nil {
		return m.Cert
	}
	return nil
}

func (m *RevokeCertificateWithRegRequest) GetCode() int64 {
	if m != nil && m.Code != nil {
		return *m.Code
	}
	return 0
}

func (m *RevokeCertificateWithRegRequest) GetRegID() int64 {
	if m != nil && m.RegID != nil {
		return *m.RegID
	}
	return 0
}

type AdministrativelyRevokeCertificateRequest struct {
	Cert             []byte  `protobuf:"bytes,1,opt,name=cert" json:"cert,omitempty"`
	Code             *int64  `protobuf:"varint,2,opt,name=code" json:"code,omitempty"`
	AdminName        *string `protobuf:"bytes,3,opt,name=adminName" json:"adminName,omitempty"`
	XXX_unrecognized []byte  `json:"-"`
}

func (m *AdministrativelyRevokeCertificateRequest) Reset() {
	*m = AdministrativelyRevokeCertificateRequest{}
}
func (m *AdministrativelyRevokeCertificateRequest) String() string { return proto1.CompactTextString(m) }
func (*AdministrativelyRevokeCertificateRequest) ProtoMessage()    {}
func (*AdministrativelyRevokeCertificateRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor0, []int{5}
}

func (m *AdministrativelyRevokeCertificateRequest) GetCert() []byte {
	if m != nil {
		return m.Cert
	}
	return nil
}

func (m *AdministrativelyRevokeCertificateRequest) GetCode() int64 {
	if m != nil && m.Code != nil {
		return *m.Code
	}
	return 0
}

func (m *AdministrativelyRevokeCertificateRequest) GetAdminName() string {
	if m != nil && m.AdminName != nil {
		return *m.AdminName
	}
	return ""
}

type NewOrderRequest struct {
	RegistrationID   *int64   `protobuf:"varint,1,opt,name=registrationID" json:"registrationID,omitempty"`
	Names            []string `protobuf:"bytes,2,rep,name=names" json:"names,omitempty"`
	XXX_unrecognized []byte   `json:"-"`
}

func (m *NewOrderRequest) Reset()                    { *m = NewOrderRequest{} }
func (m *NewOrderRequest) String() string            { return proto1.CompactTextString(m) }
func (*NewOrderRequest) ProtoMessage()               {}
func (*NewOrderRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{6} }

func (m *NewOrderRequest) GetRegistrationID() int64 {
	if m != nil && m.RegistrationID != nil {
		return *m.RegistrationID
	}
	return 0
}

func (m *NewOrderRequest) GetNames() []string {
	if m != nil {
		return m.Names
	}
	return nil
}

type FinalizeOrderRequest struct {
	Order            *core.Order `protobuf:"bytes,1,opt,name=order" json:"order,omitempty"`
	Csr              []byte      `protobuf:"bytes,2,opt,name=csr" json:"csr,omitempty"`
	XXX_unrecognized []byte      `json:"-"`
}

func (m *FinalizeOrderRequest) Reset()                    { *m = FinalizeOrderRequest{} }
func (m *FinalizeOrderRequest) String() string            { return proto1.CompactTextString(m) }
func (*FinalizeOrderRequest) ProtoMessage()               {}
func (*FinalizeOrderRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{7} }

func (m *FinalizeOrderRequest) GetOrder() *core.Order {
	if m != nil {
		return m.Order
	}
	return nil
}

func (m *FinalizeOrderRequest) GetCsr() []byte {
	if m != nil {
		return m.Csr
	}
	return nil
}

func init() {
	proto1.RegisterType((*NewAuthorizationRequest)(nil), "ra.NewAuthorizationRequest")
	proto1.RegisterType((*NewCertificateRequest)(nil), "ra.NewCertificateRequest")
	proto1.RegisterType((*UpdateRegistrationRequest)(nil), "ra.UpdateRegistrationRequest")
	proto1.RegisterType((*UpdateAuthorizationRequest)(nil), "ra.UpdateAuthorizationRequest")
	proto1.RegisterType((*RevokeCertificateWithRegRequest)(nil), "ra.RevokeCertificateWithRegRequest")
	proto1.RegisterType((*AdministrativelyRevokeCertificateRequest)(nil), "ra.AdministrativelyRevokeCertificateRequest")
	proto1.RegisterType((*NewOrderRequest)(nil), "ra.NewOrderRequest")
	proto1.RegisterType((*FinalizeOrderRequest)(nil), "ra.FinalizeOrderRequest")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for RegistrationAuthority service

type RegistrationAuthorityClient interface {
	NewRegistration(ctx context.Context, in *core.Registration, opts ...grpc.CallOption) (*core.Registration, error)
	NewAuthorization(ctx context.Context, in *NewAuthorizationRequest, opts ...grpc.CallOption) (*core.Authorization, error)
	NewCertificate(ctx context.Context, in *NewCertificateRequest, opts ...grpc.CallOption) (*core.Certificate, error)
	UpdateRegistration(ctx context.Context, in *UpdateRegistrationRequest, opts ...grpc.CallOption) (*core.Registration, error)
	UpdateAuthorization(ctx context.Context, in *UpdateAuthorizationRequest, opts ...grpc.CallOption) (*core.Authorization, error)
	RevokeCertificateWithReg(ctx context.Context, in *RevokeCertificateWithRegRequest, opts ...grpc.CallOption) (*core.Empty, error)
	DeactivateRegistration(ctx context.Context, in *core.Registration, opts ...grpc.CallOption) (*core.Empty, error)
	DeactivateAuthorization(ctx context.Context, in *core.Authorization, opts ...grpc.CallOption) (*core.Empty, error)
	AdministrativelyRevokeCertificate(ctx context.Context, in *AdministrativelyRevokeCertificateRequest, opts ...grpc.CallOption) (*core.Empty, error)
	NewOrder(ctx context.Context, in *NewOrderRequest, opts ...grpc.CallOption) (*core.Order, error)
	FinalizeOrder(ctx context.Context, in *FinalizeOrderRequest, opts ...grpc.CallOption) (*core.Empty, error)
}

type registrationAuthorityClient struct {
	cc *grpc.ClientConn
}

func NewRegistrationAuthorityClient(cc *grpc.ClientConn) RegistrationAuthorityClient {
	return &registrationAuthorityClient{cc}
}

func (c *registrationAuthorityClient) NewRegistration(ctx context.Context, in *core.Registration, opts ...grpc.CallOption) (*core.Registration, error) {
	out := new(core.Registration)
	err := grpc.Invoke(ctx, "/ra.RegistrationAuthority/NewRegistration", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *registrationAuthorityClient) NewAuthorization(ctx context.Context, in *NewAuthorizationRequest, opts ...grpc.CallOption) (*core.Authorization, error) {
	out := new(core.Authorization)
	err := grpc.Invoke(ctx, "/ra.RegistrationAuthority/NewAuthorization", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *registrationAuthorityClient) NewCertificate(ctx context.Context, in *NewCertificateRequest, opts ...grpc.CallOption) (*core.Certificate, error) {
	out := new(core.Certificate)
	err := grpc.Invoke(ctx, "/ra.RegistrationAuthority/NewCertificate", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *registrationAuthorityClient) UpdateRegistration(ctx context.Context, in *UpdateRegistrationRequest, opts ...grpc.CallOption) (*core.Registration, error) {
	out := new(core.Registration)
	err := grpc.Invoke(ctx, "/ra.RegistrationAuthority/UpdateRegistration", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *registrationAuthorityClient) UpdateAuthorization(ctx context.Context, in *UpdateAuthorizationRequest, opts ...grpc.CallOption) (*core.Authorization, error) {
	out := new(core.Authorization)
	err := grpc.Invoke(ctx, "/ra.RegistrationAuthority/UpdateAuthorization", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *registrationAuthorityClient) RevokeCertificateWithReg(ctx context.Context, in *RevokeCertificateWithRegRequest, opts ...grpc.CallOption) (*core.Empty, error) {
	out := new(core.Empty)
	err := grpc.Invoke(ctx, "/ra.RegistrationAuthority/RevokeCertificateWithReg", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *registrationAuthorityClient) DeactivateRegistration(ctx context.Context, in *core.Registration, opts ...grpc.CallOption) (*core.Empty, error) {
	out := new(core.Empty)
	err := grpc.Invoke(ctx, "/ra.RegistrationAuthority/DeactivateRegistration", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *registrationAuthorityClient) DeactivateAuthorization(ctx context.Context, in *core.Authorization, opts ...grpc.CallOption) (*core.Empty, error) {
	out := new(core.Empty)
	err := grpc.Invoke(ctx, "/ra.RegistrationAuthority/DeactivateAuthorization", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *registrationAuthorityClient) AdministrativelyRevokeCertificate(ctx context.Context, in *AdministrativelyRevokeCertificateRequest, opts ...grpc.CallOption) (*core.Empty, error) {
	out := new(core.Empty)
	err := grpc.Invoke(ctx, "/ra.RegistrationAuthority/AdministrativelyRevokeCertificate", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *registrationAuthorityClient) NewOrder(ctx context.Context, in *NewOrderRequest, opts ...grpc.CallOption) (*core.Order, error) {
	out := new(core.Order)
	err := grpc.Invoke(ctx, "/ra.RegistrationAuthority/NewOrder", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *registrationAuthorityClient) FinalizeOrder(ctx context.Context, in *FinalizeOrderRequest, opts ...grpc.CallOption) (*core.Empty, error) {
	out := new(core.Empty)
	err := grpc.Invoke(ctx, "/ra.RegistrationAuthority/FinalizeOrder", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for RegistrationAuthority service

type RegistrationAuthorityServer interface {
	NewRegistration(context.Context, *core.Registration) (*core.Registration, error)
	NewAuthorization(context.Context, *NewAuthorizationRequest) (*core.Authorization, error)
	NewCertificate(context.Context, *NewCertificateRequest) (*core.Certificate, error)
	UpdateRegistration(context.Context, *UpdateRegistrationRequest) (*core.Registration, error)
	UpdateAuthorization(context.Context, *UpdateAuthorizationRequest) (*core.Authorization, error)
	RevokeCertificateWithReg(context.Context, *RevokeCertificateWithRegRequest) (*core.Empty, error)
	DeactivateRegistration(context.Context, *core.Registration) (*core.Empty, error)
	DeactivateAuthorization(context.Context, *core.Authorization) (*core.Empty, error)
	AdministrativelyRevokeCertificate(context.Context, *AdministrativelyRevokeCertificateRequest) (*core.Empty, error)
	NewOrder(context.Context, *NewOrderRequest) (*core.Order, error)
	FinalizeOrder(context.Context, *FinalizeOrderRequest) (*core.Empty, error)
}

func RegisterRegistrationAuthorityServer(s *grpc.Server, srv RegistrationAuthorityServer) {
	s.RegisterService(&_RegistrationAuthority_serviceDesc, srv)
}

func _RegistrationAuthority_NewRegistration_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(core.Registration)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistrationAuthorityServer).NewRegistration(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ra.RegistrationAuthority/NewRegistration",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistrationAuthorityServer).NewRegistration(ctx, req.(*core.Registration))
	}
	return interceptor(ctx, in, info, handler)
}

func _RegistrationAuthority_NewAuthorization_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(NewAuthorizationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistrationAuthorityServer).NewAuthorization(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ra.RegistrationAuthority/NewAuthorization",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistrationAuthorityServer).NewAuthorization(ctx, req.(*NewAuthorizationRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _RegistrationAuthority_NewCertificate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(NewCertificateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistrationAuthorityServer).NewCertificate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ra.RegistrationAuthority/NewCertificate",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistrationAuthorityServer).NewCertificate(ctx, req.(*NewCertificateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _RegistrationAuthority_UpdateRegistration_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateRegistrationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistrationAuthorityServer).UpdateRegistration(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ra.RegistrationAuthority/UpdateRegistration",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistrationAuthorityServer).UpdateRegistration(ctx, req.(*UpdateRegistrationRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _RegistrationAuthority_UpdateAuthorization_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateAuthorizationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistrationAuthorityServer).UpdateAuthorization(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ra.RegistrationAuthority/UpdateAuthorization",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistrationAuthorityServer).UpdateAuthorization(ctx, req.(*UpdateAuthorizationRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _RegistrationAuthority_RevokeCertificateWithReg_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RevokeCertificateWithRegRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistrationAuthorityServer).RevokeCertificateWithReg(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ra.RegistrationAuthority/RevokeCertificateWithReg",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistrationAuthorityServer).RevokeCertificateWithReg(ctx, req.(*RevokeCertificateWithRegRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _RegistrationAuthority_DeactivateRegistration_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(core.Registration)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistrationAuthorityServer).DeactivateRegistration(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ra.RegistrationAuthority/DeactivateRegistration",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistrationAuthorityServer).DeactivateRegistration(ctx, req.(*core.Registration))
	}
	return interceptor(ctx, in, info, handler)
}

func _RegistrationAuthority_DeactivateAuthorization_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(core.Authorization)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistrationAuthorityServer).DeactivateAuthorization(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ra.RegistrationAuthority/DeactivateAuthorization",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistrationAuthorityServer).DeactivateAuthorization(ctx, req.(*core.Authorization))
	}
	return interceptor(ctx, in, info, handler)
}

func _RegistrationAuthority_AdministrativelyRevokeCertificate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AdministrativelyRevokeCertificateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistrationAuthorityServer).AdministrativelyRevokeCertificate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ra.RegistrationAuthority/AdministrativelyRevokeCertificate",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistrationAuthorityServer).AdministrativelyRevokeCertificate(ctx, req.(*AdministrativelyRevokeCertificateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _RegistrationAuthority_NewOrder_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(NewOrderRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistrationAuthorityServer).NewOrder(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ra.RegistrationAuthority/NewOrder",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistrationAuthorityServer).NewOrder(ctx, req.(*NewOrderRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _RegistrationAuthority_FinalizeOrder_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(FinalizeOrderRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistrationAuthorityServer).FinalizeOrder(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ra.RegistrationAuthority/FinalizeOrder",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistrationAuthorityServer).FinalizeOrder(ctx, req.(*FinalizeOrderRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _RegistrationAuthority_serviceDesc = grpc.ServiceDesc{
	ServiceName: "ra.RegistrationAuthority",
	HandlerType: (*RegistrationAuthorityServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "NewRegistration",
			Handler:    _RegistrationAuthority_NewRegistration_Handler,
		},
		{
			MethodName: "NewAuthorization",
			Handler:    _RegistrationAuthority_NewAuthorization_Handler,
		},
		{
			MethodName: "NewCertificate",
			Handler:    _RegistrationAuthority_NewCertificate_Handler,
		},
		{
			MethodName: "UpdateRegistration",
			Handler:    _RegistrationAuthority_UpdateRegistration_Handler,
		},
		{
			MethodName: "UpdateAuthorization",
			Handler:    _RegistrationAuthority_UpdateAuthorization_Handler,
		},
		{
			MethodName: "RevokeCertificateWithReg",
			Handler:    _RegistrationAuthority_RevokeCertificateWithReg_Handler,
		},
		{
			MethodName: "DeactivateRegistration",
			Handler:    _RegistrationAuthority_DeactivateRegistration_Handler,
		},
		{
			MethodName: "DeactivateAuthorization",
			Handler:    _RegistrationAuthority_DeactivateAuthorization_Handler,
		},
		{
			MethodName: "AdministrativelyRevokeCertificate",
			Handler:    _RegistrationAuthority_AdministrativelyRevokeCertificate_Handler,
		},
		{
			MethodName: "NewOrder",
			Handler:    _RegistrationAuthority_NewOrder_Handler,
		},
		{
			MethodName: "FinalizeOrder",
			Handler:    _RegistrationAuthority_FinalizeOrder_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "ra/proto/ra.proto",
}

func init() { proto1.RegisterFile("ra/proto/ra.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 585 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xa4, 0x55, 0x6b, 0x6f, 0xd2, 0x50,
	0x18, 0x06, 0x3a, 0xe6, 0xf6, 0x4e, 0xd9, 0xf6, 0x32, 0x5c, 0x57, 0x6f, 0xac, 0x26, 0x0b, 0x5e,
	0xc2, 0x92, 0x7d, 0x32, 0x59, 0x8c, 0xce, 0xe1, 0x12, 0xa2, 0x61, 0x49, 0x13, 0x63, 0xb2, 0x2f,
	0x7a, 0x2c, 0xaf, 0xd0, 0x08, 0x2d, 0x9e, 0x1e, 0x40, 0xf8, 0x13, 0xfe, 0x01, 0x7f, 0xac, 0xe9,
	0x39, 0x87, 0xf5, 0x42, 0xc9, 0x5c, 0xfc, 0x76, 0xfa, 0x5e, 0x9e, 0xf7, 0xf6, 0x3c, 0x29, 0xec,
	0x72, 0x76, 0x3c, 0xe2, 0x81, 0x08, 0x8e, 0x39, 0x6b, 0xca, 0x07, 0x96, 0x38, 0xb3, 0x6a, 0x6e,
	0xc0, 0x49, 0x3b, 0xa2, 0xa7, 0x72, 0xd9, 0x57, 0xb0, 0xdf, 0xa1, 0xe9, 0xd9, 0x58, 0xf4, 0x03,
	0xee, 0xcd, 0x99, 0xf0, 0x02, 0xdf, 0xa1, 0x9f, 0x63, 0x0a, 0x05, 0x3e, 0x83, 0x32, 0x1b, 0x8b,
	0xfe, 0xdc, 0x2c, 0xd6, 0x8b, 0x8d, 0xad, 0x93, 0x6a, 0x53, 0xa6, 0xa5, 0x43, 0x55, 0x04, 0xee,
	0x41, 0x99, 0x53, 0xaf, 0xdd, 0x32, 0x4b, 0xf5, 0x62, 0xc3, 0x70, 0xd4, 0x87, 0xfd, 0x06, 0x6a,
	0x1d, 0x9a, 0x9e, 0x13, 0x17, 0xde, 0x77, 0xcf, 0x65, 0x82, 0x16, 0xc8, 0x3b, 0x60, 0xb8, 0x21,
	0x97, 0xb8, 0x77, 0x9d, 0xe8, 0xb9, 0x02, 0x20, 0x80, 0x83, 0x4f, 0xa3, 0xae, 0x4c, 0xec, 0x79,
	0xa1, 0xe0, 0xa9, 0xf6, 0x8e, 0x60, 0xed, 0x1b, 0x0b, 0x49, 0x77, 0x87, 0xaa, 0xbb, 0x54, 0xa0,
	0xf4, 0xe3, 0x73, 0x58, 0x1f, 0x4b, 0x10, 0x89, 0x9d, 0x1f, 0xa9, 0x23, 0xec, 0x3f, 0x45, 0xb0,
	0x54, 0xc5, 0xff, 0xdd, 0xc8, 0x11, 0x54, 0xdc, 0x3e, 0x1b, 0x0c, 0xc8, 0xef, 0x51, 0xdb, 0xef,
	0xd2, 0x2f, 0x3d, 0x59, 0xc6, 0x8a, 0x2f, 0x60, 0x83, 0x53, 0x38, 0x0a, 0xfc, 0x90, 0x4c, 0x43,
	0xa2, 0x6e, 0x2b, 0xd4, 0xf3, 0x45, 0x9c, 0x73, 0x1d, 0x60, 0x7f, 0x81, 0x27, 0x0e, 0x4d, 0x82,
	0x1f, 0x94, 0xd8, 0xe9, 0x67, 0x4f, 0xf4, 0x1d, 0xea, 0x2d, 0x5a, 0x44, 0x58, 0x73, 0x89, 0x0b,
	0xbd, 0x5b, 0xf9, 0x96, 0xb6, 0xa0, 0x4b, 0xba, 0x03, 0xf9, 0x8e, 0x17, 0x6e, 0x24, 0x17, 0x3e,
	0x82, 0xc6, 0x59, 0x77, 0xe8, 0xf9, 0x7a, 0x33, 0x13, 0x1a, 0xcc, 0x96, 0x0a, 0xde, 0xb6, 0xd2,
	0x43, 0xd8, 0x64, 0x11, 0x66, 0x87, 0x0d, 0xd5, 0x88, 0x9b, 0x4e, 0x6c, 0xb0, 0x2f, 0x61, 0xbb,
	0x43, 0xd3, 0x4b, 0xde, 0x25, 0x1e, 0x1f, 0xb6, 0xc2, 0x13, 0xc7, 0x69, 0xb7, 0x64, 0x09, 0xc3,
	0xc9, 0x58, 0xa3, 0x11, 0x7c, 0x36, 0xa4, 0xd0, 0x2c, 0xd5, 0x8d, 0xc6, 0xa6, 0xa3, 0x3e, 0xec,
	0x0f, 0xb0, 0x77, 0xe1, 0xf9, 0x6c, 0xe0, 0xcd, 0x29, 0x85, 0x7a, 0x08, 0xe5, 0x20, 0xfa, 0xd6,
	0xb7, 0xdb, 0x52, 0x5b, 0x56, 0x21, 0xca, 0xb3, 0xa0, 0x65, 0xe9, 0x9a, 0x96, 0x27, 0xbf, 0xd7,
	0xa1, 0x96, 0x24, 0x8a, 0x3e, 0xb5, 0x98, 0xe1, 0xa9, 0xec, 0x3b, 0xe9, 0xc3, 0x1c, 0x62, 0x59,
	0x39, 0x36, 0xbb, 0x80, 0x17, 0xb0, 0x93, 0x15, 0x1d, 0x3e, 0x68, 0x72, 0xd6, 0x5c, 0x21, 0x45,
	0x2b, 0x8f, 0x69, 0x76, 0x01, 0xdf, 0x42, 0x25, 0x2d, 0x30, 0x3c, 0xd0, 0x28, 0xcb, 0xf7, 0xb2,
	0x76, 0x35, 0xaf, 0x62, 0x8f, 0x5d, 0xc0, 0x36, 0xe0, 0xb2, 0xc2, 0xf0, 0x51, 0x84, 0xb2, 0x52,
	0x79, 0x2b, 0x86, 0xfa, 0x08, 0xd5, 0x1c, 0xe9, 0xe0, 0xe3, 0x18, 0xeb, 0x36, 0xa3, 0x75, 0xc0,
	0x5c, 0x45, 0x75, 0x7c, 0x1a, 0x41, 0xde, 0x20, 0x04, 0x4b, 0x1f, 0xf8, 0xfd, 0x70, 0x24, 0x66,
	0x76, 0x01, 0x4f, 0xe1, 0x7e, 0x8b, 0x98, 0x2b, 0xbc, 0x49, 0x76, 0xd8, 0xbc, 0xb3, 0x65, 0x92,
	0x5f, 0xc3, 0x7e, 0x9c, 0x9c, 0x1e, 0x2f, 0xaf, 0xfd, 0x6c, 0xfa, 0x57, 0x38, 0xbc, 0x51, 0x55,
	0xf8, 0x32, 0x1a, 0xea, 0x5f, 0xc5, 0x97, 0xad, 0xd0, 0x84, 0x8d, 0x85, 0x8a, 0xb0, 0xaa, 0x29,
	0x90, 0x64, 0xbf, 0x95, 0xa4, 0xbb, 0x5d, 0xc0, 0x57, 0x70, 0x2f, 0x25, 0x12, 0x34, 0xa3, 0xa4,
	0x3c, 0xdd, 0x64, 0x2a, 0xbd, 0xbb, 0x73, 0x55, 0x96, 0x3f, 0x8e, 0xbf, 0x01, 0x00, 0x00, 0xff,
	0xff, 0xcb, 0xa1, 0xb0, 0xeb, 0x67, 0x06, 0x00, 0x00,
}
