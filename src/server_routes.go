package main

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"
)

// How installed end-node servers are given out (version 3.14.0):
//
//	direct    the person gets the link of the server itself;
//	panel     the person connects to the main server (the panel's) and leaves through this server;
//	balancer  the server is one more node of the balancer pool, the balancer checks it and picks it like the others.
//
// For the last two the main server enters the end-node with a key of its own: the user "_gw" that the panel adds to the list of
// users of such a server. The key derives from the secrets of the panel, so nothing is stored.

const gwUserName = "_gw"

// gwUUID is the key with which the main server (and the balancer pool) enters the end-node server.
func gwUUID(cfg *Config, serverID int64) string {
	return modeUUID(derive(cfg.Reality.PrivateKey+cfg.TestSecret, "endnode-gateway"), "gw"+strconv.FormatInt(serverID, 10))
}

// srvNodeID is the number of the virtual external node of the link number i of a server (far above the numbers of real nodes).
func srvNodeID(serverID int64, i int) int64 { return 1_000_000_000_000 + serverID*1000 + int64(i) }

// serverUsable says whether the server may be given out now: it is on, has told its links at least once.
func serverUsable(sv RemoteServer) bool {
	return sv.Enabled && sv.Kind == "endnode" && sv.LastSeen != nil && len(sv.Info.Links) > 0
}

// serverLinkName is the label of a link in the client list.
func serverLinkName(sv RemoteServer, t LinkTmpl) string {
	if t.Title != "" {
		return sv.Name + " · " + t.Title
	}
	return sv.Name
}

// gatewayLink is the link with which the main server enters the end-node server by the template.
func gatewayLink(cfg *Config, sv RemoteServer, t LinkTmpl) (string, bool) {
	return fillTemplate(t, "endnode", User{UUID: gwUUID(cfg, sv.ID)}, serverLinkName(sv, t))
}

// serverLines are the lines a user gets for one server of a category, by the way the server is given out.
func serverLines(cfg *Config, u User, sv RemoteServer) []string {
	if !serverUsable(sv) {
		return nil
	}
	var out []string
	for i, t := range sv.Info.Links {
		switch sv.Route {
		case routePanel:
			out = append(out, userLink(cfg, serverLinkName(sv, t), modeUUID(u.UUID, extMode(srvNodeID(sv.ID, i)))))
		case routeBalancer:
			// the server works inside the balancer: the person has it through the balancers of the main server
		default:
			if l, ok := fillTemplate(t, sv.Kind, u, serverLinkName(sv, t)); ok {
				out = append(out, l)
			}
		}
	}
	return out
}

// serverExtNodes are the virtual external nodes of a server given out through the main server.
func serverExtNodes(cfg *Config, sv RemoteServer) []*extNode {
	if !serverUsable(sv) || sv.Route != routePanel {
		return nil
	}
	var out []*extNode
	for i, t := range sv.Info.Links {
		if l, ok := gatewayLink(cfg, sv, t); ok {
			out = append(out, &extNode{ID: srvNodeID(sv.ID, i), Name: serverLinkName(sv, t), Link: l, Mode: modeVia})
		}
	}
	return out
}

// poolNodes are the nodes of a server that works inside the balancer.
func poolNodes(cfg *Config, sv RemoteServer) []*Node {
	if !serverUsable(sv) || sv.Route != routeBalancer {
		return nil
	}
	var out []*Node
	for i, t := range sv.Info.Links {
		l, ok := gatewayLink(cfg, sv, t)
		if !ok {
			continue
		}
		n := parseLink(l)
		if n == nil || n.Outbound == nil {
			continue
		}
		h := sha1.Sum([]byte(fmt.Sprintf("endnode-server|%d|%d", sv.ID, i)))
		n.ID, n.Name, n.Link = hex.EncodeToString(h[:]), serverLinkName(sv, t), l
		out = append(out, n)
	}
	return out
}

// refreshPoolServers keeps the nodes of the servers in the balancer mode in the pool (both channels); it runs with every refresh of the registry.
func (s *Store) refreshPoolServers(ctx context.Context, cfg *Config, list []RemoteServer) {
	for _, sv := range list {
		if sv.Kind != "endnode" {
			continue
		}
		ns := poolNodes(cfg, sv)
		if len(ns) == 0 {
			if sv.Route != routeBalancer || !sv.Enabled {
				_, _ = s.pool.Exec(ctx, `DELETE FROM nodes WHERE source=$1`, serverSource(sv.ID))
			}
			continue
		}
		for _, pool := range []string{chanAdmin, chanUsers} {
			if err := s.UpsertNodesPool(ctx, ns, serverSource(sv.ID), pool); err != nil {
				log.Printf("servers: pool nodes of %s: %v", sv.Name, err)
				break
			}
		}
	}
}
