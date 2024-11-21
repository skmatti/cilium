package ciliumconfig

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/gke/features"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "cilium-config")

const (
	CiliumConfigMapName         = "cilium-config"
	GoogleOverrideConfigMapName = "cilium-config-emergency-override"
)

func GetCiliumConfig(ctx context.Context, clientset k8sClient.Clientset) (*corev1.ConfigMap, error) {
	cm, found := getConfigMap(ctx, clientset, CiliumConfigMapName)
	if !found {
		return nil, fmt.Errorf("fetch ConfigMap kube-system/%s", CiliumConfigMapName)
	}

	if !features.GlobalConfig.EnableGoogleConfigOverride {
		return cm, nil
	}

	cmOverride, found := getConfigMap(ctx, clientset, GoogleOverrideConfigMapName)
	if !found || cmOverride.Data == nil {
		return cm, nil
	}

	overriddenCM := cm.DeepCopy()
	for k, v := range cmOverride.Data {
		log.Infof("Override config map entry from %s with value from %s, new entry: {%s: %s}", CiliumConfigMapName, GoogleOverrideConfigMapName, k, v)
		overriddenCM.Data[k] = v
	}

	return overriddenCM, nil
}

func GetIDRelevantLabelsFilter(ctx context.Context, cs k8sClient.Clientset) ([]string, error) {
	cm, err := GetCiliumConfig(ctx, cs)
	if err != nil {
		return nil, err
	}

	if cm.Data == nil {
		return nil, nil
	}

	// Turns a string into a string slice. Whitespaces separate filter entries.
	// https://docs.cilium.io/en/stable/operations/performance/scalability/identity-relevant-labels/
	filter := strings.Fields(cm.Data["labels"])

	return filter, nil
}

func InitLabelsFilter(ctx context.Context, logger *slog.Logger, cs k8sClient.Clientset) error {
	idRelevantLabelsFilter, err := GetIDRelevantLabelsFilter(ctx, cs)
	if err != nil {
		return fmt.Errorf("start Cilium Identity controller: %v", err)
	}
	if err := labelsfilter.ParseLabelPrefixCfg(idRelevantLabelsFilter, []string{}, ""); err != nil {
		return fmt.Errorf("start Cilium Identity controller: %v", err)
	}
	logger.Info("Identity relevant labels filter", "filter", idRelevantLabelsFilter)
	return nil
}

func getConfigMap(ctx context.Context, clientset k8sClient.Clientset, cmName string) (*corev1.ConfigMap, bool) {
	maxRetries := 5
	waitDuration := 1 * time.Second
	attempt := 1

	var cm *corev1.ConfigMap
	var err error
	for attempt <= maxRetries {
		cm, err = clientset.CoreV1().ConfigMaps(metav1.NamespaceSystem).Get(ctx, cmName, metav1.GetOptions{})
		if err == nil {
			return cm, true
		}

		time.Sleep(waitDuration)
		attempt++
	}

	log.Warnf("Failed to GET %s ConfigMap, error: %v", cmName, err)
	return nil, false
}
