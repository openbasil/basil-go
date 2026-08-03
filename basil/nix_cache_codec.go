package basil

import (
	"fmt"
	"unicode/utf8"

	"github.com/openbasil/basil-go/internal/pb"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

type nixCacheProtoCodec struct{}

// Name deliberately remains proto so an ordinary gRPC protobuf server can
// serve these calls. ForceCodec scopes this stricter implementation to one
// Nix cache RPC; it is never registered as the process-wide proto codec.
func (nixCacheProtoCodec) Name() string { return "proto" }

func (nixCacheProtoCodec) Marshal(value any) ([]byte, error) {
	message, ok := value.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("basil: strict Nix codec cannot marshal %T", value)
	}
	raw, err := proto.Marshal(message)
	if err != nil {
		return nil, err
	}
	if err := preflightNixCacheProto(raw, message); err != nil {
		return nil, err
	}
	return raw, nil
}

func (nixCacheProtoCodec) Unmarshal(raw []byte, value any) error {
	message, ok := value.(proto.Message)
	if !ok {
		return fmt.Errorf("basil: strict Nix codec cannot unmarshal %T", value)
	}
	if err := preflightNixCacheProto(raw, message); err != nil {
		return err
	}
	return proto.Unmarshal(raw, message)
}

type nixCacheSchema uint8

const (
	nixDescribeRequest nixCacheSchema = iota
	nixDescribeResponse
	nixEnrollRequest
	nixEnrollResponse
	nixSignRequest
	nixSignResponse
)

type nixCacheFieldKind uint8

const (
	nixKeyID nixCacheFieldKind = iota
	nixKeyName
	nixPublicKey
	nixIdentifier
	nixProfile
	nixFingerprint
	nixSignature
	nixBackendVersion
	nixEnrollmentDisposition
)

func preflightNixCacheProto(raw []byte, message proto.Message) error {
	schema, maximum, fields, err := nixCacheMessageSchema(message)
	if err != nil {
		return err
	}
	if len(raw) > maximum {
		return fmt.Errorf("basil: Nix cache protobuf is %d bytes; maximum is %d", len(raw), maximum)
	}

	var seen uint64
	for len(raw) != 0 {
		number, wireType, consumed := protowire.ConsumeTag(raw)
		if consumed < 0 {
			return fmt.Errorf("basil: invalid Nix cache protobuf tag: %w", protowire.ParseError(consumed))
		}
		raw = raw[consumed:]
		kind, expectedWire, ok := nixCacheFieldRule(schema, number)
		if !ok {
			return fmt.Errorf("basil: Nix cache protobuf has unknown field %d", number)
		}
		bit := uint64(1) << (number - 1)
		if seen&bit != 0 {
			return fmt.Errorf("basil: Nix cache protobuf has duplicate field %d", number)
		}
		if wireType != expectedWire {
			return fmt.Errorf("basil: Nix cache protobuf field %d has wire type %d; expected %d", number, wireType, expectedWire)
		}

		switch expectedWire {
		case protowire.BytesType:
			value, length := protowire.ConsumeBytes(raw)
			if length < 0 {
				return fmt.Errorf("basil: invalid Nix cache protobuf field %d: %w", number, protowire.ParseError(length))
			}
			if err := validateNixCacheBytes(number, kind, value); err != nil {
				return err
			}
			raw = raw[length:]
		case protowire.VarintType:
			value, length := protowire.ConsumeVarint(raw)
			if length < 0 {
				return fmt.Errorf("basil: invalid Nix cache protobuf field %d: %w", number, protowire.ParseError(length))
			}
			if err := validateNixCacheVarint(number, kind, value); err != nil {
				return err
			}
			raw = raw[length:]
		default:
			return fmt.Errorf("basil: unsupported Nix cache protobuf wire type %d", expectedWire)
		}
		seen |= bit
	}

	required := uint64(1)<<fields - 1
	if seen != required {
		for number := protowire.Number(1); number <= fields; number++ {
			if seen&(uint64(1)<<(number-1)) == 0 {
				return fmt.Errorf("basil: Nix cache protobuf is missing required field %d", number)
			}
		}
	}
	return nil
}

func nixCacheMessageSchema(message proto.Message) (nixCacheSchema, int, protowire.Number, error) {
	switch message.(type) {
	case *pb.DescribeNixCacheKeyRequest:
		return nixDescribeRequest, describeNixCacheKeyRequestMax, 3, nil
	case *pb.DescribeNixCacheKeyResponse:
		return nixDescribeResponse, describeNixCacheKeyResponseMax, 5, nil
	case *pb.EnrollNixCacheKeyRequest:
		return nixEnrollRequest, enrollNixCacheKeyRequestMax, 3, nil
	case *pb.EnrollNixCacheKeyResponse:
		return nixEnrollResponse, enrollNixCacheKeyResponseMax, 6, nil
	case *pb.SignNixCacheFingerprintRequest:
		return nixSignRequest, signNixCacheFingerprintRequestMax, 5, nil
	case *pb.SignNixCacheFingerprintResponse:
		return nixSignResponse, signNixCacheFingerprintResponseMax, 6, nil
	default:
		return 0, 0, 0, fmt.Errorf("basil: strict Nix codec does not support %T", message)
	}
}

func nixCacheFieldRule(schema nixCacheSchema, number protowire.Number) (nixCacheFieldKind, protowire.Type, bool) {
	switch schema {
	case nixDescribeRequest, nixEnrollRequest:
		switch number {
		case 1:
			return nixKeyID, protowire.BytesType, true
		case 2, 3:
			return nixIdentifier, protowire.BytesType, true
		}
	case nixDescribeResponse:
		return nixCacheIdentityField(number, 4)
	case nixEnrollResponse:
		if number == 4 {
			return nixEnrollmentDisposition, protowire.VarintType, true
		}
		return nixCacheIdentityField(number, 5)
	case nixSignRequest:
		switch number {
		case 1:
			return nixKeyID, protowire.BytesType, true
		case 2:
			return nixProfile, protowire.BytesType, true
		case 3:
			return nixFingerprint, protowire.BytesType, true
		case 4, 5:
			return nixIdentifier, protowire.BytesType, true
		}
	case nixSignResponse:
		switch number {
		case 1:
			return nixKeyName, protowire.BytesType, true
		case 2:
			return nixPublicKey, protowire.BytesType, true
		case 3:
			return nixBackendVersion, protowire.VarintType, true
		case 4:
			return nixSignature, protowire.BytesType, true
		case 5, 6:
			return nixIdentifier, protowire.BytesType, true
		}
	}
	return 0, 0, false
}

func nixCacheIdentityField(number protowire.Number, firstID protowire.Number) (nixCacheFieldKind, protowire.Type, bool) {
	switch number {
	case 1:
		return nixKeyName, protowire.BytesType, true
	case 2:
		return nixPublicKey, protowire.BytesType, true
	case 3:
		return nixBackendVersion, protowire.VarintType, true
	case firstID, firstID + 1:
		return nixIdentifier, protowire.BytesType, true
	default:
		return 0, 0, false
	}
}

func validateNixCacheBytes(number protowire.Number, kind nixCacheFieldKind, value []byte) error {
	switch kind {
	case nixKeyID:
		if !utf8.Valid(value) || len(value) < 1 || len(value) > 256 {
			return fmt.Errorf("basil: Nix cache protobuf field %d must be 1..=256 valid UTF-8 bytes", number)
		}
		for _, octet := range value {
			if octet < 0x20 || octet == 0x7f {
				return fmt.Errorf("basil: Nix cache protobuf field %d contains a control byte", number)
			}
		}
	case nixKeyName:
		if !validNixCacheKeyName(string(value)) {
			return fmt.Errorf("basil: Nix cache protobuf field %d is not a valid key name", number)
		}
	case nixPublicKey:
		if len(value) != 32 {
			return fmt.Errorf("basil: Nix cache protobuf field %d must be 32 bytes", number)
		}
	case nixIdentifier:
		if len(value) != 16 || allZeroBytes(value) {
			return fmt.Errorf("basil: Nix cache protobuf field %d must be 16 nonzero bytes", number)
		}
	case nixProfile:
		if string(value) != "PATH_INFO_V1" {
			return fmt.Errorf("basil: Nix cache protobuf field %d must equal PATH_INFO_V1", number)
		}
	case nixFingerprint:
		if len(value) < 1 || len(value) > nixCacheFingerprintMax {
			return fmt.Errorf("basil: Nix cache protobuf field %d must be 1..=%d bytes", number, nixCacheFingerprintMax)
		}
	case nixSignature:
		if len(value) != 64 {
			return fmt.Errorf("basil: Nix cache protobuf field %d must be 64 bytes", number)
		}
	default:
		return fmt.Errorf("basil: Nix cache protobuf field %d has an invalid bytes rule", number)
	}
	return nil
}

func validateNixCacheVarint(number protowire.Number, kind nixCacheFieldKind, value uint64) error {
	switch kind {
	case nixBackendVersion:
		if value != 1 {
			return fmt.Errorf("basil: Nix cache protobuf field %d must equal 1", number)
		}
	case nixEnrollmentDisposition:
		if value != 1 && value != 2 {
			return fmt.Errorf("basil: Nix cache protobuf field %d has invalid enum value %d", number, value)
		}
	default:
		return fmt.Errorf("basil: Nix cache protobuf field %d has an invalid varint rule", number)
	}
	return nil
}

func allZeroBytes(value []byte) bool {
	for _, octet := range value {
		if octet != 0 {
			return false
		}
	}
	return true
}
