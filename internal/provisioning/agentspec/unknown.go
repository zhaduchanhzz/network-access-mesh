package agentspec

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// UnknownField refuses a message that carries something this agent does not understand: unknown fields (proto3
// keeps them — a newer worker could send a security-relevant field an older agent would otherwise silently ignore)
// or an enum number that is not declared (proto3 enums are open). The walk covers nested messages and lists.
func UnknownField(m proto.Message) error {
	if m == nil {
		return nil
	}
	return walk(m.ProtoReflect(), "")
}

func walk(m protoreflect.Message, at string) error {
	if len(m.GetUnknown()) > 0 {
		f := at
		if f == "" {
			f = "(request)"
		}
		return malformed(f, "unknown field (the agent is older than its client, or the request is forged)")
	}
	var err error
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		name := join(at, string(fd.Name()))
		switch {
		case fd.IsMap():
			// agent.proto declares no map; a map would need the same walk over its values.
			err = malformed(name, "unexpected map field")
		case fd.IsList():
			l := v.List()
			for i := 0; i < l.Len() && err == nil; i++ {
				err = value(fd, l.Get(i), index(name, i))
			}
		default:
			err = value(fd, v, name)
		}
		return err == nil
	})
	return err
}

func value(fd protoreflect.FieldDescriptor, v protoreflect.Value, at string) error {
	switch fd.Kind() {
	case protoreflect.MessageKind, protoreflect.GroupKind:
		return walk(v.Message(), at)
	case protoreflect.EnumKind:
		if fd.Enum().Values().ByNumber(v.Enum()) == nil {
			return malformed(at, "unknown enum value")
		}
	}
	return nil
}
