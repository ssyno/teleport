package accessrequest

import (
	"testing"

	"github.com/gravitational/teleport/api/types"
	"github.com/stretchr/testify/require"
)

func TestRequestConditionParser(t *testing.T) {
	for _, tc := range []struct {
		name      string
		condition string
		req       types.AccessRequestV3
		expected  bool
		err       string
	}{
		{
			name:      "True condition",
			condition: `access_request.spec.roles.contains("role1")`,
			req: types.AccessRequestV3{
				Spec: types.AccessRequestSpecV3{
					Roles: []string{"role1", "role2"},
					SystemAnnotations: map[string][]string{
						"label1": {"somevalue"},
					},
				},
			},
			expected: true,
			err:      "",
		},
		{
			name:      "False condition",
			condition: `access_request.spec.roles.contains("role3")`,
			req: types.AccessRequestV3{
				Spec: types.AccessRequestSpecV3{
					Roles: []string{"role1", "role2"},
					SystemAnnotations: map[string][]string{
						"label1": {"somevalue"},
					},
				},
			},
			expected: false,
			err:      "",
		},
		{
			name:      "Multiple conditions",
			condition: `access_request.spec.roles.contains("role2") && access_request.spec.system_annotations["label1"].contains("someValue")`,
			req: types.AccessRequestV3{
				Spec: types.AccessRequestSpecV3{
					Roles: []string{"role1", "role2"},
					SystemAnnotations: map[string][]string{
						"label1": {"someValue"},
					},
				},
			},
			expected: true,
			err:      "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := matchAccessRequest(tc.condition, &tc.req)
			if tc.err != "" {
				require.False(t, got)
				require.ErrorContains(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expected, got)
		})
	}
}
