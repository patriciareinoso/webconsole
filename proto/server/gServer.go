// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0
//

package server

import (
	context "context"
	"net"
	"os"
	"time"

	protos "github.com/omec-project/config5g/proto/sdcoreConfig"
	"github.com/omec-project/openapi/models"
	"github.com/omec-project/webconsole/backend/factory"
	"github.com/omec-project/webconsole/backend/logger"
	"github.com/omec-project/webconsole/configapi"
	"github.com/omec-project/webconsole/configmodels"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

type ServerConfig struct{}

type ConfigServer struct {
	protos.ConfigServiceServer
	Version uint32
}

var kaep = keepalive.EnforcementPolicy{
	MinTime:             15 * time.Second, // If a client pings more than once every 5 seconds, terminate the connection
	PermitWithoutStream: true,             // Allow pings even when there are no active streams
}

var kasp = keepalive.ServerParameters{
	Time:    30 * time.Second, // Ping the client if it is idle for 5 seconds to ensure the connection is still active
	Timeout: 5 * time.Second,  // Wait 1 second for the ping ack before assuming the connection is dead
}

func StartServer(host string, confServ *ConfigServer, configMsgChan chan *configmodels.ConfigMessage) {
	// add 4G endpoints in the client list. 4G endpoints are configured in the
	// yaml file
	if os.Getenv("MANAGED_BY_CONFIG_POD") == "true" && !factory.WebUIConfig.Configuration.Mode5G {
		config := factory.GetConfig()
		if config != nil && config.Configuration != nil && config.Configuration.LteEnd != nil {
			for _, end := range config.Configuration.LteEnd {
				logger.GrpcLog.Infoln("adding client endpoint", end.NodeType, end.ConfigPushUrl)
				c, _ := getClient(end.NodeType)
				setClientConfigPushUrl(c, end.ConfigPushUrl)
				setClientConfigCheckUrl(c, end.ConfigCheckUrl)
			}
		}
	}
	// we wish to start grpc server only if we received at least one config
	// from the simapp/ROC
	configReady := make(chan bool)
	if factory.WebUIConfig.Configuration.Mode5G {
		logger.WebUILog.Debugln("instantiating in-DB subscriber authentication")
		subscriberAuthData = configapi.DatabaseSubscriberAuthenticationData{}
	} else {
		logger.WebUILog.Debugln("instantiating in-memory subscriber authentication")
		configapi.ImsiData = make(map[string]*models.AuthenticationSubscription)
		subscriberAuthData = configapi.MemorySubscriberAuthenticationData{}
	}
	go configHandler(configMsgChan, configReady)
	ready := <-configReady

	time.Sleep(2 * time.Second)

	logger.GrpcLog.Infoln("start grpc config server", ready)
	lis, err := net.Listen("tcp", host)
	if err != nil {
		logger.GrpcLog.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer(grpc.KeepaliveEnforcementPolicy(kaep), grpc.KeepaliveParams(kasp))
	protos.RegisterConfigServiceServer(grpcServer, confServ)
	if err = grpcServer.Serve(lis); err != nil {
		logger.GrpcLog.Fatalf("failed to serve: %v", err)
	}
	logger.GrpcLog.Infoln("completed grpc server goroutine")
}

func (c *ConfigServer) GetNetworkSlice(ctx context.Context, rReq *protos.NetworkSliceRequest) (*protos.NetworkSliceResponse, error) {
	logger.GrpcLog.Infof("Network Slice config req: client %v, rst counter %v", rReq.ClientId, rReq.RestartCounter)
	client, created := getClient(rReq.ClientId)
	var reqMsg clientReqMsg
	reqMsg.networkSliceReqMsg = rReq
	reqMsg.grpcRspMsg = make(chan *clientRspMsg)
	// Post the message on client handler & wait to get response
	if created {
		reqMsg.newClient = true
	}
	client.tempGrpcReq <- &reqMsg
	rResp := <-reqMsg.grpcRspMsg
	client.clientLog.Infoln("received response message from client FSM")
	return rResp.networkSliceRspMsg, nil
}

func (c *ConfigServer) NetworkSliceSubscribe(req *protos.NetworkSliceRequest, stream protos.ConfigService_NetworkSliceSubscribeServer) error {
	logger.GrpcLog.Infoln("NetworkSliceSubscribe call from client ID", req.ClientId)
	fin := make(chan bool)
	// Save the subscriber stream according to the given client ID
	client, created := getClient(req.ClientId)
	client.resStream = stream
	client.resChannel = fin

	var reqMsg clientReqMsg
	reqMsg.networkSliceReqMsg = req
	// Post the message on client handler & wait to get response
	if created {
		reqMsg.newClient = true
		client.metadataReqtd = req.MetadataRequested
	}
	client.tempGrpcReq <- &reqMsg
	ctx := stream.Context()
	// Keep this scope alive because once this scope exits - the stream is closed
	for {
		select {
		case <-fin:
			client.clientLog.Infoln("closing stream for client ID:", req.ClientId)
			delete(clientNFPool, req.ClientId)
			return nil
		case <-ctx.Done():
			client.clientLog.Infof("client ID %s has disconnected", req.ClientId)
			delete(clientNFPool, req.ClientId)
			return nil
		}
	}
}
