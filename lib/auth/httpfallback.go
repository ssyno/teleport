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

package auth

import (
	"context"
	"encoding/json"
	"net/url"
	"time"

	"github.com/gravitational/trace"
	"google.golang.org/protobuf/types/known/durationpb"

	presencepb "github.com/gravitational/teleport/api/gen/proto/go/teleport/presence/v1"
	trustpb "github.com/gravitational/teleport/api/gen/proto/go/teleport/trust/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/services"
)

// httpfallback.go holds endpoints that have been converted to gRPC
// but still need http fallback logic in the old client.

// GenerateHostCert takes the public key in the OpenSSH “authorized_keys“
// plain text format, signs it using Host Certificate Authority private key and
// returns the resulting certificate.
// TODO(noah): DELETE IN 16.0.0
func (c *Client) GenerateHostCert(
	ctx context.Context,
	key []byte,
	hostID, nodeName string,
	principals []string,
	clusterName string,
	role types.SystemRole,
	ttl time.Duration,
) ([]byte, error) {
	res, err := c.APIClient.TrustClient().GenerateHostCert(ctx, &trustpb.GenerateHostCertRequest{
		Key:         key,
		HostId:      hostID,
		NodeName:    nodeName,
		Principals:  principals,
		ClusterName: clusterName,
		Role:        string(role),
		Ttl:         durationpb.New(ttl),
	})
	if err != nil {
		switch {
		case trace.IsNotImplemented(err):
			// Fall back to HTTP implementation.
			return c.generateHostCertHTTP(
				ctx, key, hostID, nodeName, principals, clusterName, role, ttl,
			)
		default:
			return nil, trace.Wrap(err)
		}
	}
	return res.SshCertificate, nil
}

// TODO(noah): DELETE IN 16.0.0
func (c *Client) generateHostCertHTTP(
	ctx context.Context,
	key []byte,
	hostID, nodeName string,
	principals []string,
	clusterName string,
	role types.SystemRole,
	ttl time.Duration,
) ([]byte, error) {
	out, err := c.PostJSON(ctx, c.Endpoint("ca", "host", "certs"),
		generateHostCertReq{
			Key:         key,
			HostID:      hostID,
			NodeName:    nodeName,
			Principals:  principals,
			ClusterName: clusterName,
			Roles:       types.SystemRoles{role},
			TTL:         ttl,
		})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var cert string
	if err := json.Unmarshal(out.Bytes(), &cert); err != nil {
		return nil, err
	}
	return []byte(cert), nil
}

// TODO(Joerger): DELETE IN 16.0.0
func (c *Client) RotateCertAuthority(ctx context.Context, req types.RotateRequest) error {
	err := c.APIClient.RotateCertAuthority(ctx, req)
	if trace.IsNotImplemented(err) {
		// Fall back to HTTP implementation.
		_, err := c.PostJSON(ctx, c.Endpoint("authorities", string(req.Type), "rotate"), req)
		return trace.Wrap(err)
	}

	return trace.Wrap(err)
}

// TODO(Joerger): DELETE IN 16.0.0
func (c *Client) RotateExternalCertAuthority(ctx context.Context, ca types.CertAuthority) error {
	err := c.APIClient.RotateExternalCertAuthority(ctx, ca)
	if trace.IsNotImplemented(err) {
		// Fall back to HTTP implementation.
		data, err := services.MarshalCertAuthority(ca)
		if err != nil {
			return trace.Wrap(err)
		}
		_, err = c.PostJSON(ctx, c.Endpoint("authorities", string(ca.GetType()), "rotate", "external"),
			&rotateExternalCertAuthorityRawReq{CA: data})
		return trace.Wrap(err)
	}

	return trace.Wrap(err)
}

func (c *Client) createRemoteClusterLegacy(ctx context.Context, rc types.RemoteCluster) (types.RemoteCluster, error) {
	data, err := services.MarshalRemoteCluster(rc)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	args := &createRemoteClusterRawReq{
		RemoteCluster: data,
	}
	_, err = c.PostJSON(ctx, c.Endpoint("remoteclusters"), args)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	returned, err := c.getRemoteClusterLegacy(ctx, rc.GetName())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return returned, trace.Wrap(err)
}

// CreateRemoteCluster creates remote cluster resource
// TODO(noah): DELETE IN 17.0.0
func (c *Client) CreateRemoteCluster(ctx context.Context, rc types.RemoteCluster) (types.RemoteCluster, error) {
	res, err := c.APIClient.CreateRemoteCluster(ctx, rc)
	if err == nil {
		return res, nil
	}
	if !trace.IsNotImplemented(err) {
		return nil, trace.Wrap(err)
	}
	return c.createRemoteClusterLegacy(ctx, rc)
}

func (c *Client) deleteRemoteClusterLegacy(ctx context.Context, clusterName string) error {
	if clusterName == "" {
		return trace.BadParameter("missing parameter cluster name")
	}
	_, err := c.Delete(ctx, c.Endpoint("remoteclusters", clusterName))
	return trace.Wrap(err)
}

// DeleteRemoteCluster deletes remote cluster by name
// TODO(noah): DELETE IN 17.0.0
func (c *Client) DeleteRemoteCluster(ctx context.Context, name string) error {
	err := c.APIClient.DeleteRemoteCluster(ctx, name)
	if err == nil {
		return nil
	}
	if !trace.IsNotImplemented(err) {
		return trace.Wrap(err)
	}
	return c.deleteRemoteClusterLegacy(ctx, name)
}

func (c *Client) getRemoteClustersLegacy(ctx context.Context) ([]types.RemoteCluster, error) {
	out, err := c.Get(ctx, c.Endpoint("remoteclusters"), url.Values{})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var items []json.RawMessage
	if err := json.Unmarshal(out.Bytes(), &items); err != nil {
		return nil, trace.Wrap(err)
	}
	conns := make([]types.RemoteCluster, len(items))
	for i, raw := range items {
		conn, err := services.UnmarshalRemoteCluster(raw)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		conns[i] = conn
	}
	return conns, nil
}

// GetRemoteClusters returns a list of remote clusters
// Prefer using ListRemoteClusters.
// TODO(noah): DELETE IN 17.0.0
func (c *Client) GetRemoteClusters(ctx context.Context) ([]types.RemoteCluster, error) {
	var rcs []types.RemoteCluster
	pageToken := ""
	for {
		var err error
		var page []types.RemoteCluster
		page, pageToken, err = c.APIClient.ListRemoteClusters(ctx, 0, pageToken)
		if err != nil {
			if trace.IsNotImplemented(err) {
				return c.getRemoteClustersLegacy(ctx)
			}
			return nil, trace.Wrap(err)
		}
		rcs = append(rcs, page...)
		if pageToken == "" {
			return rcs, nil
		}
	}
}

func (c *Client) getRemoteClusterLegacy(ctx context.Context, clusterName string) (types.RemoteCluster, error) {
	if clusterName == "" {
		return nil, trace.BadParameter("missing cluster name")
	}
	out, err := c.Get(ctx, c.Endpoint("remoteclusters", clusterName), url.Values{})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return services.UnmarshalRemoteCluster(out.Bytes())
}

// GetRemoteCluster returns remote cluster by name
// TODO(noah): DELETE IN 17.0.0
func (c *Client) GetRemoteCluster(ctx context.Context, name string) (types.RemoteCluster, error) {
	res, err := c.APIClient.GetRemoteCluster(ctx, name)
	if err == nil {
		return res, nil
	}
	if !trace.IsNotImplemented(err) {
		return nil, trace.Wrap(err)
	}
	return c.getRemoteClusterLegacy(ctx, name)
}

// UpdateRemoteCluster updates a remote cluster.
// TODO(noah): DELETE IN 17.0.0 and update api/client.go to call new endpoint
func (c *Client) UpdateRemoteCluster(ctx context.Context, rc types.RemoteCluster) (types.RemoteCluster, error) {
	rcV3, ok := rc.(*types.RemoteClusterV3)
	if !ok {
		return nil, trace.BadParameter("unsupported remote cluster type %T", rcV3)
	}
	out, err := c.APIClient.PresenceServiceClient().UpdateRemoteCluster(ctx, &presencepb.UpdateRemoteClusterRequest{
		RemoteCluster: rcV3,
	})
	if err == nil {
		return out, nil
	}
	if !trace.IsNotImplemented(err) {
		return nil, trace.Wrap(err)
	}

	// This is a little weird during the migration period of the old endpoints
	// to grpc. Here, we need to call Update via gRPC and Get via HTTP.
	if err := c.APIClient.UpdateRemoteCluster(ctx, rc); err != nil {
		return nil, trace.Wrap(err)
	}
	fetchedRC, err := c.getRemoteClusterLegacy(ctx, rc.GetName())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return fetchedRC, nil
}
