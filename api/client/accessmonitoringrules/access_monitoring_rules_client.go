// Copyright 2024 Gravitational, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package accessmonitoringrules

import (
	"context"

	"github.com/gravitational/trace"

	accessmonitoringrulesv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/accessmonitoringrules/v1"
	"github.com/gravitational/teleport/api/types/accessmonitoringrule"
	conv "github.com/gravitational/teleport/api/types/accessmonitoringrule/convert/v1"
)

// Client is an access monitoring rules client that conforms to services.AccessMonitoringRules
// * services.AccessLists
type Client struct {
	grpcClient accessmonitoringrulesv1.AccessMonitoringRulesServiceClient
}

// NewClient returns and access monitoring rules client
func NewClient(grpcClient accessmonitoringrulesv1.AccessMonitoringRulesServiceClient) *Client {
	return &Client{
		grpcClient: grpcClient,
	}
}

// CreateAccessMonitoringRule creates the specified access monitoring rule.
func (c *Client) CreateAccessMonitoringRule(ctx context.Context, in *accessmonitoringrule.AccessMonitoringRule) (*accessmonitoringrule.AccessMonitoringRule, error) {
	req := &accessmonitoringrulesv1.CreateAccessMonitoringRuleRequest{
		AccessMonitoringRule: conv.ToProto(in),
	}
	resp, err := c.grpcClient.CreateAccessMonitoringRule(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	amr, err := conv.FromProto(resp)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return amr, nil
}

// UpdateAccessMonitoringRule updates the specified access monitoring rule.
func (c *Client) UpdateAccessMonitoringRule(ctx context.Context, in *accessmonitoringrule.AccessMonitoringRule) (*accessmonitoringrule.AccessMonitoringRule, error) {
	req := &accessmonitoringrulesv1.UpdateAccessMonitoringRuleRequest{
		AccessMonitoringRule: conv.ToProto(in),
	}
	resp, err := c.grpcClient.UpdateAccessMonitoringRule(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	amr, err := conv.FromProto(resp)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return amr, nil
}

// UpsertAccessMonitoringRule upserts the specified access monitoring rule.
func (c *Client) UpsertAccessMonitoringRule(ctx context.Context, in *accessmonitoringrule.AccessMonitoringRule) (*accessmonitoringrule.AccessMonitoringRule, error) {
	req := &accessmonitoringrulesv1.UpsertAccessMonitoringRuleRequest{
		AccessMonitoringRule: conv.ToProto(in),
	}
	resp, err := c.grpcClient.UpsertAccessMonitoringRule(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	amr, err := conv.FromProto(resp)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return amr, nil
}

// GetAccessMonitoringRule gets the specified access monitoring rule.
func (c *Client) GetAccessMonitoringRule(ctx context.Context, resourceName string) (*accessmonitoringrule.AccessMonitoringRule, error) {
	req := &accessmonitoringrulesv1.GetAccessMonitoringRuleRequest{
		ResourceName: resourceName,
	}
	resp, err := c.grpcClient.GetAccessMonitoringRule(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	amr, err := conv.FromProto(resp)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return amr, nil
}

// DeleteAccessMonitoringRule deletes the specified access monitoring rule.
func (c *Client) DeleteAccessMonitoringRule(ctx context.Context, resourceName string) error {
	req := &accessmonitoringrulesv1.DeleteAccessMonitoringRuleRequest{
		ResourceName: resourceName,
	}
	_, err := c.grpcClient.DeleteAccessMonitoringRule(ctx, req)
	return trace.Wrap(err)
}

// DeleteAllAccessMonitoringRules deletes all access monitoring rules.
func (c *Client) DeleteAllAccessMonitoringRules(ctx context.Context) error {
	req := &accessmonitoringrulesv1.DeleteAccessMonitoringRuleRequest{}
	_, err := c.grpcClient.DeleteAccessMonitoringRule(ctx, req)
	return trace.Wrap(err)
}

// ListAccessMonitoringRules lists current access monitoring rules.
func (c *Client) ListAccessMonitoringRules(ctx context.Context, pageSize int, pageToken string) ([]*accessmonitoringrule.AccessMonitoringRule, string, error) {
	resp, err := c.grpcClient.ListAccessMonitoringRules(ctx, &accessmonitoringrulesv1.ListAccessMonitoringRulesRequest{
		PageSize:  int64(pageSize),
		PageToken: pageToken,
	})
	if err != nil {
		return nil, "", trace.Wrap(err)
	}
	amrs := make([]*accessmonitoringrule.AccessMonitoringRule, len(resp.AccessMonitoringRules))
	for i, amr := range resp.AccessMonitoringRules {
		var err error
		amrs[i], err = conv.FromProto(amr)
		if err != nil {
			return nil, "", trace.Wrap(err)
		}
	}
	return amrs, resp.GetNextPageToken(), nil
}
