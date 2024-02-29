/*
Copyright 2024 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package accessrequest

import (
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/expression"
	"github.com/gravitational/teleport/lib/utils/typical"
	"github.com/gravitational/trace"
)

// accessRequestExpressionEnv holds user details that can be mapped in an
// access request condition assertion.
type accessRequestExpressionEnv struct {
	// e.g access_request.spec.roles.contains('prod-rw')
	Roles       []string
	Annotations map[string][]string
}

type accessRequestExpression typical.Expression[accessRequestExpressionEnv, any]

func parseAccessRequestExpression(expr string) (accessRequestExpression, error) {
	parser, err := newRequestConditionParser()
	parsedExpr, err := parser.Parse(expr)
	if err != nil {
		return nil, trace.Wrap(err, "parsing label expression")
	}
	return parsedExpr, nil
}

func newRequestConditionParser() (*typical.Parser[accessRequestExpressionEnv, any], error) {
	typicalEnvVar := map[string]typical.Variable{
		"true":  true,
		"false": false,
		"access_request.spec.roles": typical.DynamicVariable[accessRequestExpressionEnv](func(env accessRequestExpressionEnv) (expression.Set, error) {
			return expression.NewSet(env.Roles...), nil
		}),
		"access_request.spec.system_annotations": typical.DynamicMap[accessRequestExpressionEnv, expression.Set](func(env accessRequestExpressionEnv) (expression.Dict, error) {
			return expression.DictFromStringSliceMap(env.Annotations), nil
		}),
	}
	defParserSpec := expression.DefaultParserSpec[accessRequestExpressionEnv]()
	defParserSpec.Variables = typicalEnvVar

	requestConditionParser, err := typical.NewParser[accessRequestExpressionEnv, any](defParserSpec)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return requestConditionParser, nil
}

func matchAccessRequest(expr string, req types.AccessRequest) (bool, error) {
	parsedExpr, err := parseAccessRequestExpression(expr)
	if err != nil {
		return false, trace.Wrap(err)
	}

	match, err := parsedExpr.Evaluate(accessRequestExpressionEnv{
		Roles:       req.GetRoles(),
		Annotations: req.GetSystemAnnotations(),
	})
	if err != nil {
		return false, trace.Wrap(err, "evaluating label expression %q", expr)
	}
	if matched, ok := match.(bool); ok && matched {
		return true, nil
	}
	return false, nil
}
