package dataplanev2encryption

import (
	"context"
	"errors"
	"fmt"

	"github.com/cilium/cilium/pkg/gke/apis/dataplanev2encryption/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	expectedDpv2EncryptionCRName = "default"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "dpv2encryption")
)

// GetClient returns a k8s client with the dpv2e types. Separated out into a
// function to enable testing with a fake client.
func GetClient() (client.Client, error) {
	k8sConfig, err := k8s.CreateConfig()
	if err != nil {
		return nil, errors.New(
			fmt.Sprintf("Unable to retrieve k8s config: %v", err))
	}
	scheme := runtime.NewScheme()
	v1alpha1.AddToScheme(scheme)
	return client.New(k8sConfig, client.Options{Scheme: scheme})
}

// IsWireguard returns true if the Wireguard CRD is installed, a CR is present,
// and the values of the CR indicate that Wireguard is enabled.
func IsWireguard(c client.Client) (bool, error) {
	e := &v1alpha1.DataplaneV2Encryption{}
	if err := c.Get(context.Background(), client.ObjectKey{Name: expectedDpv2EncryptionCRName}, e); err != nil {
		// Since enabling the feature involves installing a CRD and CR, we treat
		// not found errors as "dpv2encryption disabled".
		if meta.IsNoMatchError(err) || apierrors.IsNotFound(err) {
			log.Infof("DataplaneV2Encryption CR/CRD not installed: %v", err.Error())
			return false, nil
		}
		return false, errors.New(
			fmt.Sprintf("Unable to get DataplaneV2Encryption CR: %v", err.Error()))
	}
	log.WithFields(logrus.Fields{
		"name":    e.ObjectMeta.Name,
		"enabled": e.Spec.Enabled,
		"type":    e.Spec.Type,
	}).Info("Found DataplaneV2Encryption Spec")
	return e.Spec.Enabled && e.Spec.Type == v1alpha1.WireguardDataplaneV2EncryptionType, nil
}
