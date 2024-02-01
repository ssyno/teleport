//go:build !ignore_autogenerated

/*
Teleport
Copyright (C) 2023  Gravitational, Inc.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

// Code generated by controller-gen. DO NOT EDIT.

package v1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TeleportAccessList) DeepCopyInto(out *TeleportAccessList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TeleportAccessList.
func (in *TeleportAccessList) DeepCopy() *TeleportAccessList {
	if in == nil {
		return nil
	}
	out := new(TeleportAccessList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *TeleportAccessList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TeleportAccessListList) DeepCopyInto(out *TeleportAccessListList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]TeleportAccessList, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TeleportAccessListList.
func (in *TeleportAccessListList) DeepCopy() *TeleportAccessListList {
	if in == nil {
		return nil
	}
	out := new(TeleportAccessListList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *TeleportAccessListList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TeleportAccessListSpec.
func (in *TeleportAccessListSpec) DeepCopy() *TeleportAccessListSpec {
	if in == nil {
		return nil
	}
	out := new(TeleportAccessListSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TeleportLoginRule) DeepCopyInto(out *TeleportLoginRule) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TeleportLoginRule.
func (in *TeleportLoginRule) DeepCopy() *TeleportLoginRule {
	if in == nil {
		return nil
	}
	out := new(TeleportLoginRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *TeleportLoginRule) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TeleportLoginRuleList) DeepCopyInto(out *TeleportLoginRuleList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]TeleportLoginRule, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TeleportLoginRuleList.
func (in *TeleportLoginRuleList) DeepCopy() *TeleportLoginRuleList {
	if in == nil {
		return nil
	}
	out := new(TeleportLoginRuleList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *TeleportLoginRuleList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TeleportLoginRuleSpec) DeepCopyInto(out *TeleportLoginRuleSpec) {
	*out = *in
	if in.TraitsMap != nil {
		in, out := &in.TraitsMap, &out.TraitsMap
		*out = make(map[string][]string, len(*in))
		for key, val := range *in {
			var outVal []string
			if val == nil {
				(*out)[key] = nil
			} else {
				inVal := (*in)[key]
				in, out := &inVal, &outVal
				*out = make([]string, len(*in))
				copy(*out, *in)
			}
			(*out)[key] = outVal
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TeleportLoginRuleSpec.
func (in *TeleportLoginRuleSpec) DeepCopy() *TeleportLoginRuleSpec {
	if in == nil {
		return nil
	}
	out := new(TeleportLoginRuleSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TeleportOktaImportRule) DeepCopyInto(out *TeleportOktaImportRule) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TeleportOktaImportRule.
func (in *TeleportOktaImportRule) DeepCopy() *TeleportOktaImportRule {
	if in == nil {
		return nil
	}
	out := new(TeleportOktaImportRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *TeleportOktaImportRule) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TeleportOktaImportRuleList) DeepCopyInto(out *TeleportOktaImportRuleList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]TeleportOktaImportRule, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TeleportOktaImportRuleList.
func (in *TeleportOktaImportRuleList) DeepCopy() *TeleportOktaImportRuleList {
	if in == nil {
		return nil
	}
	out := new(TeleportOktaImportRuleList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *TeleportOktaImportRuleList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TeleportOktaImportRuleMapping) DeepCopyInto(out *TeleportOktaImportRuleMapping) {
	*out = *in
	if in.Match != nil {
		in, out := &in.Match, &out.Match
		*out = make([]TeleportOktaImportRuleMatch, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.AddLabels != nil {
		in, out := &in.AddLabels, &out.AddLabels
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TeleportOktaImportRuleMapping.
func (in *TeleportOktaImportRuleMapping) DeepCopy() *TeleportOktaImportRuleMapping {
	if in == nil {
		return nil
	}
	out := new(TeleportOktaImportRuleMapping)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TeleportOktaImportRuleMatch) DeepCopyInto(out *TeleportOktaImportRuleMatch) {
	*out = *in
	if in.AppIDs != nil {
		in, out := &in.AppIDs, &out.AppIDs
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.GroupIDs != nil {
		in, out := &in.GroupIDs, &out.GroupIDs
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.AppNameRegexes != nil {
		in, out := &in.AppNameRegexes, &out.AppNameRegexes
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.GroupNameRegexes != nil {
		in, out := &in.GroupNameRegexes, &out.GroupNameRegexes
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TeleportOktaImportRuleMatch.
func (in *TeleportOktaImportRuleMatch) DeepCopy() *TeleportOktaImportRuleMatch {
	if in == nil {
		return nil
	}
	out := new(TeleportOktaImportRuleMatch)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TeleportOktaImportRuleSpec) DeepCopyInto(out *TeleportOktaImportRuleSpec) {
	*out = *in
	if in.Mappings != nil {
		in, out := &in.Mappings, &out.Mappings
		*out = make([]TeleportOktaImportRuleMapping, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TeleportOktaImportRuleSpec.
func (in *TeleportOktaImportRuleSpec) DeepCopy() *TeleportOktaImportRuleSpec {
	if in == nil {
		return nil
	}
	out := new(TeleportOktaImportRuleSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TeleportOpensshEICEServerV2) DeepCopyInto(out *TeleportOpensshEICEServerV2) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TeleportOpensshEICEServerV2.
func (in *TeleportOpensshEICEServerV2) DeepCopy() *TeleportOpensshEICEServerV2 {
	if in == nil {
		return nil
	}
	out := new(TeleportOpensshEICEServerV2)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *TeleportOpensshEICEServerV2) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TeleportOpensshEICEServerV2List) DeepCopyInto(out *TeleportOpensshEICEServerV2List) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]TeleportOpensshEICEServerV2, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TeleportOpensshEICEServerV2List.
func (in *TeleportOpensshEICEServerV2List) DeepCopy() *TeleportOpensshEICEServerV2List {
	if in == nil {
		return nil
	}
	out := new(TeleportOpensshEICEServerV2List)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *TeleportOpensshEICEServerV2List) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TeleportOpensshEICEServerV2Spec.
func (in *TeleportOpensshEICEServerV2Spec) DeepCopy() *TeleportOpensshEICEServerV2Spec {
	if in == nil {
		return nil
	}
	out := new(TeleportOpensshEICEServerV2Spec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TeleportOpensshServerV2) DeepCopyInto(out *TeleportOpensshServerV2) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TeleportOpensshServerV2.
func (in *TeleportOpensshServerV2) DeepCopy() *TeleportOpensshServerV2 {
	if in == nil {
		return nil
	}
	out := new(TeleportOpensshServerV2)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *TeleportOpensshServerV2) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TeleportOpensshServerV2List) DeepCopyInto(out *TeleportOpensshServerV2List) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]TeleportOpensshServerV2, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TeleportOpensshServerV2List.
func (in *TeleportOpensshServerV2List) DeepCopy() *TeleportOpensshServerV2List {
	if in == nil {
		return nil
	}
	out := new(TeleportOpensshServerV2List)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *TeleportOpensshServerV2List) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TeleportOpensshServerV2Spec.
func (in *TeleportOpensshServerV2Spec) DeepCopy() *TeleportOpensshServerV2Spec {
	if in == nil {
		return nil
	}
	out := new(TeleportOpensshServerV2Spec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TeleportRoleV6) DeepCopyInto(out *TeleportRoleV6) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TeleportRoleV6.
func (in *TeleportRoleV6) DeepCopy() *TeleportRoleV6 {
	if in == nil {
		return nil
	}
	out := new(TeleportRoleV6)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *TeleportRoleV6) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TeleportRoleV6List) DeepCopyInto(out *TeleportRoleV6List) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]TeleportRoleV6, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TeleportRoleV6List.
func (in *TeleportRoleV6List) DeepCopy() *TeleportRoleV6List {
	if in == nil {
		return nil
	}
	out := new(TeleportRoleV6List)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *TeleportRoleV6List) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TeleportRoleV6Spec.
func (in *TeleportRoleV6Spec) DeepCopy() *TeleportRoleV6Spec {
	if in == nil {
		return nil
	}
	out := new(TeleportRoleV6Spec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TeleportRoleV7) DeepCopyInto(out *TeleportRoleV7) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TeleportRoleV7.
func (in *TeleportRoleV7) DeepCopy() *TeleportRoleV7 {
	if in == nil {
		return nil
	}
	out := new(TeleportRoleV7)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *TeleportRoleV7) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TeleportRoleV7List) DeepCopyInto(out *TeleportRoleV7List) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]TeleportRoleV7, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TeleportRoleV7List.
func (in *TeleportRoleV7List) DeepCopy() *TeleportRoleV7List {
	if in == nil {
		return nil
	}
	out := new(TeleportRoleV7List)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *TeleportRoleV7List) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TeleportRoleV7Spec.
func (in *TeleportRoleV7Spec) DeepCopy() *TeleportRoleV7Spec {
	if in == nil {
		return nil
	}
	out := new(TeleportRoleV7Spec)
	in.DeepCopyInto(out)
	return out
}
