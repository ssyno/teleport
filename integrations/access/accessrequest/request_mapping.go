package accessrequest

import (
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/e/lib/expression"
	"github.com/gravitational/teleport/lib/utils/typical"
	"github.com/gravitational/trace"
)

// accessRequestExpressionEnv holds user details that can be mapped in an
// access request condition assertion.
type accessRequestExpressionEnv struct {
	// e.g access_request.spec.roles.contains('prod-rw') && !access_request.status.notified
	Roles       []string
	Notified    bool
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
		"access_request.status.notified": typical.DynamicVariable[accessRequestExpressionEnv](func(env accessRequestExpressionEnv) (bool, error) {
			return env.Notified, nil
		}),
		"access_request.spec.system_annotations": typical.DynamicMap[accessRequestExpressionEnv, expression.Set](func(env accessRequestExpressionEnv) (expression.Dict, error) {
			return expression.DictFromStringSliceMap(env.Annotations), nil
		}),
	}
	// TODO: Replace defaultParserSpec in new traits expression parser with more limited one
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
	notified := false
	if status := req.GetStatus(); status != nil {
		notified = status.Notified
	}

	match, err := parsedExpr.Evaluate(accessRequestExpressionEnv{
		Roles:       req.GetRoles(),
		Notified:    notified,
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
