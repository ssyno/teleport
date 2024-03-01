/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package common

import (
	"context"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/gravitational/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/config"
	"github.com/gravitational/teleport/lib/modules"
	"github.com/gravitational/teleport/lib/tbot/testhelpers"
	"github.com/gravitational/teleport/lib/utils"
)

func TestEditResources(t *testing.T) {
	t.Parallel()
	log := utils.NewLoggerForTests()
	fc, fds := testhelpers.DefaultConfig(t)
	_ = testhelpers.MakeAndRunTestAuthServer(t, log, fc, fds)
	rootClient := testhelpers.MakeDefaultAuthClient(t, log, fc)

	tests := []struct {
		kind string
		edit func(t *testing.T, fc *config.FileConfig, clt auth.ClientI)
	}{
		{
			kind: types.KindGithubConnector,
			edit: testEditGithubConnector,
		},
		{
			kind: types.KindRole,
			edit: testEditRole,
		},
		{
			kind: types.KindUser,
			edit: testEditUser,
		},
		{
			kind: types.KindClusterAuthPreference,
			edit: testEditAuthPreference,
		},
	}

	for _, test := range tests {
		t.Run(test.kind, func(t *testing.T) {
			test.edit(t, fc, rootClient)
		})
	}
}

func testEditGithubConnector(t *testing.T, fc *config.FileConfig, clt auth.ClientI) {
	ctx := context.Background()

	expected, err := types.NewGithubConnector("github", types.GithubConnectorSpecV3{
		ClientID:     "12345",
		ClientSecret: "678910",
		RedirectURL:  "https://proxy.example.com/v1/webapi/github/callback",
		Display:      "Github",
		TeamsToRoles: []types.TeamRolesMapping{
			{
				Organization: "acme",
				Team:         "users",
				Roles:        []string{"access", "editor", "auditor"},
			},
		},
	})
	require.NoError(t, err, "creating initial connector resource")
	created, err := clt.CreateGithubConnector(ctx, expected.(*types.GithubConnectorV3))
	require.NoError(t, err, "persisting initial connector resource")

	editor := func(name string) error {
		f, err := os.Create(name)
		if err != nil {
			return trace.Wrap(err, "opening file to edit")
		}

		expected.SetRevision(created.GetRevision())
		expected.SetClientID("abcdef")

		collection := &connectorsCollection{github: []types.GithubConnector{expected}}
		return trace.NewAggregate(writeYAML(collection, f), f.Close())

	}

	// Edit the connector and validate that the expected field is updated.
	_, err = runEditCommand(t, fc, []string{"edit", "connector/github"}, withEditor(editor))
	require.NoError(t, err, "expected editing github connector to succeed")

	actual, err := clt.GetGithubConnector(ctx, expected.GetName(), true)
	require.NoError(t, err, "retrieving github connector after edit")
	assert.NotEqual(t, created.GetClientID(), actual.GetClientID(), "client id should have been modified by edit")
	require.Empty(t, cmp.Diff(expected, actual, cmpopts.IgnoreFields(types.Metadata{}, "ID", "Revision", "Namespace")))

	// Try editing the connector a second time. This time the revisions will not match
	// since the created revision is stale.
	_, err = runEditCommand(t, fc, []string{"edit", "connector/github"}, withEditor(editor))
	assert.Error(t, err, "stale connector was allowed to be updated")
	require.ErrorIs(t, err, backend.ErrIncorrectRevision, "expected an incorrect revision error, got %T", err)
}

func testEditRole(t *testing.T, fc *config.FileConfig, clt auth.ClientI) {
	ctx := context.Background()

	expected, err := types.NewRole("test-role", types.RoleSpecV6{})
	require.NoError(t, err, "creating initial role resource")
	created, err := clt.CreateRole(ctx, expected.(*types.RoleV6))
	require.NoError(t, err, "persisting initial role resource")

	editor := func(name string) error {
		f, err := os.Create(name)
		if err != nil {
			return trace.Wrap(err, "opening file to edit")
		}

		expected.SetRevision(created.GetRevision())
		expected.SetLogins(types.Allow, []string{"abcdef"})

		collection := &roleCollection{roles: []types.Role{expected}}
		return trace.NewAggregate(writeYAML(collection, f), f.Close())

	}

	// Edit the role and validate that the expected field is updated.
	_, err = runEditCommand(t, fc, []string{"edit", "role/test-role"}, withEditor(editor))
	require.NoError(t, err, "expected editing role to succeed")

	actual, err := clt.GetRole(ctx, expected.GetName())
	require.NoError(t, err, "retrieving role after edit")
	assert.NotEqual(t, created.GetLogins(types.Allow), actual.GetLogins(types.Allow), "logins should have been modified by edit")
	require.Empty(t, cmp.Diff(expected, actual, cmpopts.IgnoreFields(types.Metadata{}, "ID", "Revision")))

	// Try editing the role a second time. This time the revisions will not match
	// since the created revision is stale.
	_, err = runEditCommand(t, fc, []string{"edit", "role/test-role"}, withEditor(editor))
	assert.Error(t, err, "stale role was allowed to be updated")
	require.ErrorIs(t, err, backend.ErrIncorrectRevision, "expected an incorrect revision error, got %T", err)
}

func testEditUser(t *testing.T, fc *config.FileConfig, clt auth.ClientI) {
	ctx := context.Background()

	expected, err := types.NewUser("llama")
	require.NoError(t, err, "creating initial user resource")
	created, err := clt.CreateUser(ctx, expected.(*types.UserV2))
	require.NoError(t, err, "persisting initial user resource")

	editor := func(name string) error {
		f, err := os.Create(name)
		if err != nil {
			return trace.Wrap(err, "opening file to edit")
		}

		expected.SetRevision(created.GetRevision())
		expected.SetLogins([]string{"abcdef"})
		expected.SetCreatedBy(created.GetCreatedBy())

		collection := &userCollection{users: []types.User{expected}}
		return trace.NewAggregate(writeYAML(collection, f), f.Close())

	}

	// Edit the user and validate that the expected field is updated.
	_, err = runEditCommand(t, fc, []string{"edit", "user/llama"}, withEditor(editor))
	require.NoError(t, err, "expected editing role to succeed")

	actual, err := clt.GetUser(ctx, expected.GetName(), true)
	require.NoError(t, err, "retrieving user after edit")
	assert.NotEqual(t, created.GetLogins(), actual.GetLogins(), "logins should have been modified by edit")
	require.Empty(t, cmp.Diff(expected, actual, cmpopts.IgnoreFields(types.Metadata{}, "ID", "Revision")))

	// Try editing the user a second time. This time the revisions will not match
	// since the created revision is stale.
	_, err = runEditCommand(t, fc, []string{"edit", "user/llama"}, withEditor(editor))
	assert.Error(t, err, "stale user was allowed to be updated")
	require.ErrorIs(t, err, backend.ErrIncorrectRevision, "expected an incorrect revision error, got %T", err)
}

func testEditAuthPreference(t *testing.T, fc *config.FileConfig, clt auth.ClientI) {
	ctx := context.Background()

	expected := types.DefaultAuthPreference()
	initial, err := clt.GetAuthPreference(ctx)
	require.NoError(t, err, "getting initial auth preference")

	editor := func(name string) error {
		f, err := os.Create(name)
		if err != nil {
			return trace.Wrap(err, "opening file to edit")
		}

		expected.SetRevision(initial.GetRevision())
		expected.SetSecondFactor(constants.SecondFactorOff)

		collection := &authPrefCollection{authPref: expected}
		return trace.NewAggregate(writeYAML(collection, f), f.Close())

	}

	// Edit the cap and validate that the expected field is updated.
	_, err = runEditCommand(t, fc, []string{"edit", "cap"}, withEditor(editor))
	require.NoError(t, err, "expected editing cap to succeed")

	actual, err := clt.GetAuthPreference(ctx)
	require.NoError(t, err, "retrieving cap after edit")
	assert.NotEqual(t, initial.GetSecondFactor(), actual.GetSecondFactor(), "second factor should have been modified by edit")
	require.Empty(t, cmp.Diff(expected, actual, cmpopts.IgnoreFields(types.Metadata{}, "ID", "Revision", "Labels")))
	assert.Equal(t, types.OriginDynamic, actual.Origin())

	// Try editing the cap a second time. This time the revisions will not match
	// since the created revision is stale.
	_, err = runEditCommand(t, fc, []string{"edit", "cap"}, withEditor(editor))
	assert.Error(t, err, "stale cap was allowed to be updated")
	require.ErrorIs(t, err, backend.ErrIncorrectRevision, "expected an incorrect revision error, got %T", err)
}

// TestEditEnterpriseResources asserts that tctl edit
// behaves as expected for enterprise resources. These resources cannot
// be tested in parallel because they alter the modules to enable features.
// The tests are grouped to amortize the cost of creating and auth server since
// that is the most expensive part of testing editing the resource.
func TestEditEnterpriseResources(t *testing.T) {
	modules.SetTestModules(t, &modules.TestModules{
		TestBuildType: modules.BuildEnterprise,
		TestFeatures: modules.Features{
			OIDC: true,
			SAML: true,
		},
	})
	log := utils.NewLoggerForTests()
	fc, fds := testhelpers.DefaultConfig(t)
	_ = testhelpers.MakeAndRunTestAuthServer(t, log, fc, fds)
	rootClient := testhelpers.MakeDefaultAuthClient(t, log, fc)

	tests := []struct {
		kind string
		edit func(t *testing.T, fc *config.FileConfig, clt auth.ClientI)
	}{
		{
			kind: types.KindOIDCConnector,
			edit: testEditOIDCConnector,
		},
		{
			kind: types.KindSAMLConnector,
			edit: testEditSAMLConnector,
		},
	}

	for _, test := range tests {
		t.Run(test.kind, func(t *testing.T) {
			test.edit(t, fc, rootClient)
		})
	}
}

func testEditOIDCConnector(t *testing.T, fc *config.FileConfig, clt auth.ClientI) {
	ctx := context.Background()
	expected, err := types.NewOIDCConnector("oidc", types.OIDCConnectorSpecV3{
		ClientID:     "12345",
		ClientSecret: "678910",
		RedirectURLs: []string{"https://proxy.example.com/v1/webapi/github/callback"},
		Display:      "OIDC",
		ClaimsToRoles: []types.ClaimMapping{
			{
				Claim: "test",
				Value: "test",
				Roles: []string{"access", "editor", "auditor"},
			},
		},
	})
	require.NoError(t, err, "creating initial connector resource")
	created, err := clt.CreateOIDCConnector(ctx, expected.(*types.OIDCConnectorV3))
	require.NoError(t, err, "persisting initial connector resource")

	editor := func(name string) error {
		f, err := os.Create(name)
		if err != nil {
			return trace.Wrap(err, "opening file to edit")
		}

		expected.SetRevision(created.GetRevision())
		expected.SetClientID("abcdef")

		collection := &connectorsCollection{oidc: []types.OIDCConnector{expected}}
		return trace.NewAggregate(writeYAML(collection, f), f.Close())

	}

	// Edit the connector and validate that the expected field is updated.
	_, err = runEditCommand(t, fc, []string{"edit", "connector/oidc"}, withEditor(editor))
	require.NoError(t, err, "expected editing oidc connector to succeed")

	actual, err := clt.GetOIDCConnector(ctx, expected.GetName(), false)
	require.NoError(t, err, "retrieving oidc connector after edit")
	require.Empty(t, cmp.Diff(created, actual, cmpopts.IgnoreFields(types.Metadata{}, "ID", "Revision", "Namespace"),
		cmpopts.IgnoreFields(types.OIDCConnectorSpecV3{}, "ClientID", "ClientSecret"),
	))
	require.NotEqual(t, created.GetClientID(), actual.GetClientID(), "client id should have been modified by edit")
	require.Equal(t, expected.GetClientID(), actual.GetClientID(), "client id should match the retrieved connector")

	// Try editing the connector a second time. This time the revisions will not match
	// since the created revision is stale.
	_, err = runEditCommand(t, fc, []string{"edit", "connector/oidc"}, withEditor(editor))
	assert.Error(t, err, "stale connector was allowed to be updated")
	require.ErrorIs(t, err, backend.ErrIncorrectRevision, "expected an incorrect revision error, got %T", err)
}

func testEditSAMLConnector(t *testing.T, fc *config.FileConfig, clt auth.ClientI) {
	ctx := context.Background()

	expected, err := types.NewSAMLConnector("saml", types.SAMLConnectorSpecV2{
		AssertionConsumerService: "original-acs",
		EntityDescriptor: `<?xml version="1.0" encoding="UTF-8"?>
    <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="test">
      <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:KeyDescriptor use="signing">
          <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:X509Data>
              <ds:X509Certificate></ds:X509Certificate>
            </ds:X509Data>
          </ds:KeyInfo>
        </md:KeyDescriptor>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="test" />
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="test" />
      </md:IDPSSODescriptor>
    </md:EntityDescriptor>`,
		Display: "SAML",
		AttributesToRoles: []types.AttributeMapping{
			{
				Name:  "test",
				Value: "test",
				Roles: []string{"access"},
			},
		},
	})
	require.NoError(t, err, "creating initial connector resource")

	created, err := clt.CreateSAMLConnector(ctx, expected.(*types.SAMLConnectorV2))
	require.NoError(t, err, "persisting initial connector resource")

	editor := func(name string) error {
		f, err := os.Create(name)
		if err != nil {
			return trace.Wrap(err, "opening file to edit")
		}

		expected.SetRevision(created.GetRevision())
		expected.SetSigningKeyPair(created.GetSigningKeyPair())
		expected.SetAssertionConsumerService("updated-acs")

		collection := &connectorsCollection{saml: []types.SAMLConnector{expected}}
		return trace.NewAggregate(writeYAML(collection, f), f.Close())

	}

	// Edit the connector and validate that the expected field is updated.
	_, err = runEditCommand(t, fc, []string{"edit", "connector/saml"}, withEditor(editor))
	require.NoError(t, err, "expected editing saml connector to succeed")

	actual, err := clt.GetSAMLConnector(ctx, expected.GetName(), true)
	require.NoError(t, err, "retrieving saml connector after edit")
	require.Empty(t, cmp.Diff(created, actual, cmpopts.IgnoreFields(types.Metadata{}, "ID", "Revision", "Namespace"),
		cmpopts.IgnoreFields(types.SAMLConnectorSpecV2{}, "AssertionConsumerService"),
	))
	require.NotEqual(t, created.GetAssertionConsumerService(), actual.GetAssertionConsumerService(), "acs should have been modified by edit")
	require.Equal(t, expected.GetAssertionConsumerService(), actual.GetAssertionConsumerService(), "acs should match the retrieved connector")

	// Try editing the connector a second time this, time the revisions will not match
	// since the created revision is stale.
	_, err = runEditCommand(t, fc, []string{"edit", "connector/saml"}, withEditor(editor))
	assert.Error(t, err, "stale connector was allowed to be updated")
	require.ErrorIs(t, err, backend.ErrIncorrectRevision, "expected an incorrect revision error, got %T", err)
}
