/*
 * Teleport
 * Copyright (C) 2024  Gravitational, Inc.
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

package aws_sync

import (
	"context"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/gravitational/trace"
	"golang.org/x/sync/errgroup"

	accessgraphv1alpha "github.com/gravitational/teleport/gen/proto/go/accessgraph/v1alpha"
	"github.com/gravitational/teleport/lib/cloud"
)

// pageSize is the default page size to use when fetching AWS resources
// from the AWS API for endpoints that support pagination.
const pageSize int64 = 500

// Config is the configuration for the AWS fetcher.
type Config struct {
	// CloudClients is the cloud clients to use when fetching AWS resources.
	CloudClients cloud.Clients
	// AccountID is the AWS account ID to use when fetching resources.
	AccountID string
	// Regions is the list of AWS regions to fetch resources from.
	Regions []string
	// AssumeRole is the configuration for assuming an AWS role.
	AssumeRole *AssumeRole
	// Integration is the name of the AWS integration to use when fetching resources.
	Integration string
}

// AssumeRole is the configuration for assuming an AWS role.
type AssumeRole struct {
	// RoleARN is the ARN of the role to assume.
	RoleARN string
	// ExternalID is the external ID to use when assuming the role.
	ExternalID string
}

// awsFetcher is a fetcher that fetches AWS resources.
type awsFetcher struct {
	Config
}

// AWSSync is the interface for fetching AWS resources.
type AWSSync interface {
	// Poll polls all AWS resources and returns the result.
	Poll(ctx context.Context) (*Resources, error)
}

// Resources is a collection of polled AWS resources.
type Resources struct {
	// Users is the list of AWS users.
	Users []*accessgraphv1alpha.AWSUserV1
	// UserInlinePolicies is the list of inline policies configured for AWS users.
	UserInlinePolicies []*accessgraphv1alpha.AWSUserInlinePolicyV1
	// UserAttachedPolicies is the list of attached policies configured for AWS users.
	// This is a User ARN -> Policy ARN mapping and the policy document is included
	// in Policies.
	UserAttachedPolicies []*accessgraphv1alpha.AWSUserAttachedPolicies
	// UserGroups is the list of groups that AWS users are members of.
	UserGroups []*accessgraphv1alpha.AWSUserGroupsV1
	// Groups is the list of AWS groups.
	Groups []*accessgraphv1alpha.AWSGroupV1
	// GroupInlinePolicies is the list of inline policies configured for AWS groups.
	GroupInlinePolicies []*accessgraphv1alpha.AWSGroupInlinePolicyV1
	// GroupAttachedPolicies is the list of attached policies configured for AWS groups.
	// This is a Group ARN -> Policy ARN mapping and the policy document is included
	GroupAttachedPolicies []*accessgraphv1alpha.AWSGroupAttachedPolicies
	// Instances is the list of AWS EC2 instances.
	Instances []*accessgraphv1alpha.AWSInstanceV1
	// Policies is the list of AWS IAM policies and their policy documents.
	Policies []*accessgraphv1alpha.AWSPolicyV1
	// S3Buckets is the list of AWS S3 buckets.
	S3Buckets []*accessgraphv1alpha.AWSS3BucketV1
	// Roles is the list of AWS IAM roles.
	Roles []*accessgraphv1alpha.AWSRoleV1
	// RoleInlinePolicies is the list of inline policies configured for AWS roles.
	RoleInlinePolicies []*accessgraphv1alpha.AWSRoleInlinePolicyV1
	// RoleAttachedPolicies is the list of attached policies configured for AWS roles.
	// This is a Role ARN -> Policy ARN mapping and the policy document is included
	RoleAttachedPolicies []*accessgraphv1alpha.AWSRoleAttachedPolicies
	// InstanceProfiles is the list of AWS IAM instance profiles.
	InstanceProfiles []*accessgraphv1alpha.AWSInstanceProfileV1
}

// NewAWSFetcher creates a new AWS fetcher.
func NewAWSFetcher(ctx context.Context, cfg Config) (AWSSync, error) {
	a := &awsFetcher{
		Config: cfg,
	}
	accountID, err := a.getAccountId(context.Background())
	if err != nil {
		return nil, trace.Wrap(err, "failed to get AWS account ID")
	}
	a.AccountID = accountID
	return a, nil
}

// Poll retrieves all AWS resources and returns the result.
// Poll is a blocking call and will return when all resources have been fetched.
// It's possible that the call returns Resources and an error at the same time
// if some resources were fetched successfully and some were not.
func (a *awsFetcher) Poll(ctx context.Context) (*Resources, error) {
	result, err := a.poll(ctx)
	return result, trace.Wrap(err)
}

func (a *awsFetcher) poll(ctx context.Context) (*Resources, error) {
	eGroup, ctx := errgroup.WithContext(ctx)
	// Set the limit for the number of concurrent pollers running in parallel.
	// This is to prevent the number of concurrent pollers from growing too large
	// and causing the AWS API to throttle requests.
	eGroup.SetLimit(5)
	var (
		errs   []error
		errMu  sync.Mutex
		result = &Resources{}
	)
	// collectErr collects an error and adds it to the list of errors.
	// errors are collected in parallel and are not returned until all
	// resources have been fetched.
	collectErr := func(err error) {
		errMu.Lock()
		defer errMu.Unlock()
		errs = append(errs, err)
	}

	// fetch AWS users and their associated resources.
	// - inline policies
	// - attached policies
	// - user groups they are members of
	eGroup.Go(a.pollAWSUsers(ctx, result, collectErr))

	// fetch AWS groups and their associated resources.
	// - inline policies
	// - attached policies
	eGroup.Go(a.pollAWSRoles(ctx, result, collectErr))

	// fetch AWS groups and their associated resources.
	// - inline policies
	// - attached policies
	eGroup.Go(a.pollAWSGroups(ctx, result, collectErr))

	// fetch AWS EC2 instances and their associated resources.
	// - instance profiles
	eGroup.Go(a.pollAWSEC2Instances(ctx, result, collectErr))

	// fetch AWS IAM policies and their policy documents.
	eGroup.Go(a.pollAWSPolicies(ctx, result, collectErr))

	// fetch AWS S3 buckets.
	eGroup.Go(a.pollAWSS3Buckets(ctx, result, collectErr))

	if err := eGroup.Wait(); err != nil {
		return nil, trace.Wrap(err)
	}
	return result, trace.NewAggregate(errs...)
}

// getAWSOptions returns a list of AWSAssumeRoleOptionFn to be used when
// creating AWS clients.
func (a *awsFetcher) getAWSOptions() []cloud.AWSAssumeRoleOptionFn {
	opts := []cloud.AWSAssumeRoleOptionFn{
		cloud.WithCredentialsMaybeIntegration(a.Config.Integration),
	}

	if a.Config.AssumeRole != nil {
		opts = append(opts, cloud.WithAssumeRole(a.Config.AssumeRole.RoleARN, a.Config.AssumeRole.ExternalID))
	}
	return opts
}

func (a *awsFetcher) getAccountId(ctx context.Context) (string, error) {
	stsClient, err := a.CloudClients.GetAWSSTSClient(
		ctx,
		"", /* region is empty because groups are global */
		a.getAWSOptions()...,
	)
	if err != nil {
		return "", trace.Wrap(err)
	}

	input := &sts.GetCallerIdentityInput{}
	req, err := stsClient.GetCallerIdentityWithContext(ctx, input)
	if err != nil {
		return "", trace.Wrap(err)
	}

	return aws.StringValue(req.Account), nil
}
