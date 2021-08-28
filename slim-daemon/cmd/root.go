// Copyright 2016-2020 Authors of Cilium
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

package cmd

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/slim-daemon/k8s"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	daemonSubsys = "daemon"
)

func init() {
	nodeTypes.SetName(os.Getenv("NODE_NAME"))
}

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, daemonSubsys)

	RootCmd = &cobra.Command{
		Use:   "cilium-slim-agent",
		Short: "Run the slim cilium agent",
		Run: func(cmd *cobra.Command, args []string) {
			initEnv(cmd)
			runDaemon()
		},
	}
)

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func initEnv(cmd *cobra.Command) {
	// Prepopulate option.Config with options from CLI.
	option.Config.Populate()

	k8s.Configure(option.Config.K8sAPIServer, option.Config.K8sKubeConfigPath, defaults.K8sClientQPSLimit, defaults.K8sClientBurst)

	option.Config.Debug = true
	if option.Config.Debug {
		logging.SetLogLevelToDebug()
	}

	if err := k8s.Init(option.Config); err != nil {
		log.WithError(err).Fatal("Unable to connect to Kubernetes apiserver")
	}
}

func runDaemon() {
	log.Info("Initializing daemon")

	if err := labelsfilter.ParseLabelPrefixCfg(option.Config.Labels, option.Config.LabelPrefixFile); err != nil {
		log.WithError(err).Fatal("Unable to parse Label prefix configuration")
	}

	daemon := NewDaemon()
	daemon.Run()

	errs := make(chan error, 1)
	select {
	case err := <-errs:
		if err != nil {
			log.WithError(err).Fatal("Error returned from non-returning Serve() call")
		}
	}
}

func init() {
	flags := RootCmd.Flags()

	flags.String(option.K8sAPIServer, "", "Kubernetes API server URL")
	option.BindEnv(option.K8sAPIServer)

	flags.String(option.K8sKubeConfigPath, "", "Absolute path of the kubernetes kubeconfig file")
	option.BindEnv(option.K8sKubeConfigPath)

	flags.Duration(option.IdentityChangeGracePeriod, defaults.IdentityChangeGracePeriod, "Time to wait before using new identity on endpoint identity change")
	option.BindEnv(option.IdentityChangeGracePeriod)

	flags.Duration(option.AllocatorListTimeoutName, defaults.AllocatorListTimeout, "Timeout for listing allocator state before exiting")
	option.BindEnv(option.AllocatorListTimeoutName)

	flags.Duration(option.KVstorePeriodicSync, defaults.KVstorePeriodicSync, "Periodic KVstore synchronization interval")
	option.BindEnv(option.KVstorePeriodicSync)

	viper.BindPFlags(flags)
}

type Daemon struct {
	watcher *k8sWatcher
}

func NewDaemon() *Daemon {
	d := &Daemon{
		watcher: NewK8sWatcher(),
	}

	return d
}

func (d *Daemon) Run() {
	client := k8s.WatcherClient()
	d.initNode(client)
	d.watcher.initPodWatcher(client)
}

func (d *Daemon) initNode(client *k8s.K8sClient) {
	v1Node, err := client.CoreV1().Nodes().Get(context.Background(), nodeTypes.GetName(), meta_v1.GetOptions{})
	if err != nil {
		log.WithError(err).WithField("node", nodeTypes.GetName()).Fatal("Failed to get node")
		os.Exit(1)
	}

	for _, address := range v1Node.Status.Addresses {
		if address.Type == corev1.NodeInternalIP {
			ip := net.ParseIP(address.Address)
			if ip.To4() != nil {
				node.SetIPv4(ip)
			} else if ip.To16() != nil {
				node.SetIPv6(ip)
			}
		}
	}
}
