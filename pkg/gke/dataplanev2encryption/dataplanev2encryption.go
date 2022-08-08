package dataplanev2encryption

import (
	"context"
	"github.com/cilium/cilium/pkg/gke/apis/dataplanev2encryption/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func IsWireguard() bool {
	k8sConfig, err := k8s.CreateConfig()
	if err != nil {
		log.Debugf("Unable to create k8s config: %v", err.Error())
		return false
	}

	scheme := runtime.NewScheme()
	v1alpha1.AddToScheme(scheme)
	k8sClient, err := client.New(k8sConfig, client.Options{Scheme: scheme})
	if err != nil {
		log.Debugf("Unable to create k8s client: %v", err.Error())
		return false
	}

	e := &v1alpha1.DataplaneV2Encryption{}
	if err := k8sClient.Get(context.Background(), client.ObjectKey{Name: "default"}, e); err != nil {
		log.Debugf("Unable to get DataplaneV2Encryption CR: %v", err.Error())
		return false
	}

	log.WithFields(log.Fields{
		"name":    e.ObjectMeta.Name,
		"enabled": e.Spec.Enabled,
		"type":    e.Spec.Type,
	}).Info("Found DataplaneV2Encryption Spec")
	return e.Spec.Enabled && e.Spec.Type == v1alpha1.WireguardDataplaneV2EncryptionType
}
