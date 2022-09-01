/*
Copyright 2022 Gravitational, Inc.

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

package cassandra

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"

	"github.com/datastax/go-cassandra-native-protocol/message"
	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/defaults"
	libevents "github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/srv/db/cassandra/protocol"
	"github.com/gravitational/teleport/lib/srv/db/common"
	"github.com/gravitational/teleport/lib/srv/db/common/role"
	"github.com/gravitational/teleport/lib/utils"
)

func init() {
	common.RegisterEngine(newEngine, defaults.ProtocolCassandra)
}

// newEngine create new Cassandra engine.
func newEngine(ec common.EngineConfig) common.Engine {
	return &Engine{
		EngineConfig: ec,
	}
}

// Engine implements common.Engine.
type Engine struct {
	// EngineConfig is the common database engine configuration.
	common.EngineConfig
	// clientConn is a client connection.
	clientConn *protocol.Conn
	// sessionCtx is current session context.
	sessionCtx *common.Session
	// handshakeTriggered is set to true if handshake was triggered and
	// used to indicated that custom errors should be sent to the client.
	// Cassandra wire protocol relays on streamID to that needs to match the request value
	// so sending a custom error to the client requires to read a first message send by the client.
	handshakeTriggered bool
}

// SendError send a Cassandra ServerError to  error to the client if handshake was not yet initialized by the client.
// Cassandra wire protocol relays on streamID to that are set by the client and server response needs to
// set the correct streamID in order to get streamID SendError reads a first message send by the client.
func (e *Engine) SendError(sErr error) {
	if utils.IsOKNetworkError(sErr) || sErr == nil {
		return
	}
	e.Log.Debug("cassandra connection error: %v", sErr)
	if e.handshakeTriggered {
		return
	}

	eh := failedHandshake{error: sErr}
	if err := eh.handshake(e.clientConn, nil); err != nil {
		e.Log.Warnf("cassandra connection error: %v", sErr)
	}
}

// InitializeConnection initializes the database connection.
func (e *Engine) InitializeConnection(clientConn net.Conn, sessionCtx *common.Session) error {
	e.clientConn = protocol.NewConn(clientConn)
	e.sessionCtx = sessionCtx
	return nil
}

// HandleConnection processes the connection from Cassandra proxy coming
// over reverse tunnel.
func (e *Engine) HandleConnection(ctx context.Context, sessionCtx *common.Session) error {
	err := e.authorizeConnection(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	serverConn, err := e.connect(ctx, sessionCtx)
	if err != nil {
		return trace.Wrap(err)
	}
	defer serverConn.Close()

	e.Audit.OnSessionStart(e.Context, sessionCtx, nil)
	defer e.Audit.OnSessionEnd(e.Context, sessionCtx)

	if err := e.handshake(sessionCtx, e.clientConn, serverConn); err != nil {
		return trace.Wrap(err)
	}

	return trace.Wrap(e.handleClientServerConn(ctx, e.clientConn, serverConn))
}

func (e *Engine) handleClientServerConn(ctx context.Context, clientConn *protocol.Conn, serverConn net.Conn) error {
	errC := make(chan error, 2)
	go func() {
		err := e.handleClientConnectionWithAudit(clientConn, serverConn)
		errC <- trace.Wrap(err, "client done")
	}()
	go func() {
		err := e.handleServerConnection(clientConn, serverConn)
		errC <- trace.Wrap(err, "server done")
	}()

	var errs []error
	for i := 0; i < 2; i++ {
		select {
		case <-ctx.Done():
			return trace.Wrap(ctx.Err())
		case err := <-errC:
			if err != nil && !utils.IsOKNetworkError(errors.Unwrap(err)) && !errors.Is(err, io.EOF) {
				errs = append(errs, err)
			}
		}
	}
	return trace.NewAggregate(errs...)

}

func (e *Engine) handleClientConnectionWithAudit(clientConn *protocol.Conn, serverConn net.Conn) error {
	defer serverConn.Close()
	for {
		packet, err := clientConn.ReadPacket()
		if err != nil {
			return trace.Wrap(err)
		}
		if err := e.processPacket(packet); err != nil {
			return trace.Wrap(err)
		}
		if _, err := serverConn.Write(packet.Raw()); err != nil {
			return trace.Wrap(err)
		}
	}
}

func (e *Engine) handleServerConnection(clientConn, serverConn net.Conn) error {
	defer e.clientConn.Close()
	if _, err := io.Copy(clientConn, serverConn); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func getUsernameFromAuthResponse(msg *message.AuthResponse) (string, error) {
	// auth token contains username and password split by \0 character
	// ex: \0username\0password
	data := bytes.Split(msg.Token, []byte{0})
	if len(data) != 3 {
		return "", trace.BadParameter("failed to extract username from the auth package")
	}
	return string(data[1]), nil
}

func validateCassandraUsername(ses *common.Session, msg *message.AuthResponse) error {
	username, err := getUsernameFromAuthResponse(msg)
	if err != nil {
		return trace.Wrap(err)
	}
	if ses.DatabaseUser != username {
		return trace.AccessDenied("user %s is not authorized to access the database", username)
	}
	return nil
}

func (e *Engine) processPacket(packet *protocol.Packet) error {
	body := packet.FrameBody()
	switch msg := body.Message.(type) {
	case *message.Options:
		// Cassandra client sends options message to the server to negotiate protocol version.
		// Skip audit for this message.
	case *message.Startup:
		// Startup message is sent by the client to initialize the cassandra handshake.
		// Skip audit for this message.
	case *message.AuthResponse:
		if err := validateCassandraUsername(e.sessionCtx, msg); err != nil {
			return trace.Wrap(err)
		}
	case *message.Query:
		e.Audit.OnQuery(e.Context, e.sessionCtx, common.Query{
			Query: msg.String(),
		})
	case *message.Prepare:
		e.Audit.EmitEvent(e.Context, &events.CassandraPrepare{
			Metadata: common.MakeEventMetadata(e.sessionCtx,
				libevents.DatabaseSessionCassandraPrepareEvent,
				libevents.CassandraPrepareEventCode,
			),
			UserMetadata:     common.MakeUserMetadata(e.sessionCtx),
			SessionMetadata:  common.MakeSessionMetadata(e.sessionCtx),
			DatabaseMetadata: common.MakeDatabaseMetadata(e.sessionCtx),
			Query:            msg.Query,
			Keyspace:         msg.Keyspace,
		})
	case *message.Execute:
		e.Audit.EmitEvent(e.Context, &events.CassandraExecute{
			Metadata: common.MakeEventMetadata(e.sessionCtx,
				libevents.DatabaseSessionCassandraExecuteEvent,
				libevents.CassandraExecuteEventCode,
			),
			UserMetadata:     common.MakeUserMetadata(e.sessionCtx),
			SessionMetadata:  common.MakeSessionMetadata(e.sessionCtx),
			DatabaseMetadata: common.MakeDatabaseMetadata(e.sessionCtx),
			QueryId:          hex.EncodeToString(msg.QueryId),
		})
	case *message.Batch:
		e.Audit.EmitEvent(e.Context, &events.CassandraBatch{
			Metadata: common.MakeEventMetadata(e.sessionCtx,
				libevents.DatabaseSessionCassandraBatchEvent,
				libevents.CassandraBatchEventCode,
			),
			UserMetadata:     common.MakeUserMetadata(e.sessionCtx),
			SessionMetadata:  common.MakeSessionMetadata(e.sessionCtx),
			DatabaseMetadata: common.MakeDatabaseMetadata(e.sessionCtx),
			Consistency:      msg.Consistency.String(),
			Keyspace:         msg.Keyspace,
			BatchType:        msg.Type.String(),
			Children:         batchChildToProto(msg.Children),
		})
	case *message.Register:
		e.Audit.EmitEvent(e.Context, &events.CassandraRegister{
			Metadata: common.MakeEventMetadata(e.sessionCtx,
				libevents.DatabaseSessionCassandraRegisterEvent,
				libevents.CassandraRegisterEventCode,
			),
			UserMetadata:     common.MakeUserMetadata(e.sessionCtx),
			SessionMetadata:  common.MakeSessionMetadata(e.sessionCtx),
			DatabaseMetadata: common.MakeDatabaseMetadata(e.sessionCtx),
			EventTypes:       eventTypesToString(msg.EventTypes),
		})
	case *message.Revise:
		return trace.NotImplemented("revise package is not supported")
	default:
		return trace.BadParameter("received a message with unexpected type %T", body.Message)
	}

	return nil
}

// authorizeConnection does authorization check for Cassandra connection about
// to be established.
func (e *Engine) authorizeConnection(ctx context.Context) error {
	ap, err := e.Auth.GetAuthPreference(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	mfaParams := services.AccessMFAParams{
		Verified:       e.sessionCtx.Identity.MFAVerified != "",
		AlwaysRequired: ap.GetRequireSessionMFA(),
	}

	dbRoleMatchers := role.DatabaseRoleMatchers(
		e.sessionCtx.Database.GetProtocol(),
		e.sessionCtx.DatabaseUser,
		e.sessionCtx.DatabaseName,
	)
	err = e.sessionCtx.Checker.CheckAccess(
		e.sessionCtx.Database,
		mfaParams,
		dbRoleMatchers...,
	)
	if err != nil {
		e.Audit.OnSessionStart(e.Context, e.sessionCtx, err)
		return trace.Wrap(err)
	}
	return nil
}

func (e *Engine) connect(ctx context.Context, sessionCtx *common.Session) (*protocol.Conn, error) {
	config, err := e.Auth.GetTLSConfig(ctx, sessionCtx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	tlsDialer := tls.Dialer{Config: config}
	serverConn, err := tlsDialer.DialContext(ctx, "tcp", sessionCtx.Database.GetURI())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return protocol.NewConn(serverConn), nil
}

func (e *Engine) handshake(sessionCtx *common.Session, clientConn, serverConn *protocol.Conn) error {
	auth, err := e.getAuth(sessionCtx)
	if err != nil {
		return trace.Wrap(err)
	}
	e.handshakeTriggered = true
	return auth.handleHandshake(clientConn, serverConn)
}

func (e *Engine) getAuth(sessionCtx *common.Session) (handshakeHandler, error) {
	switch {
	case sessionCtx.Database.IsAWSHosted():
		return &authAWSSigV4Auth{
			ses: sessionCtx,
		}, nil
	default:
		return &basicHandshake{ses: sessionCtx}, nil
	}
}
