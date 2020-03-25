/*
Copyright 2020 Google LLC

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

// Code generated by lister-gen. DO NOT EDIT.

package v1alpha1

import (
	v1alpha1 "github.com/cilium/cilium/pkg/gke/apis/networklogging/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// NetworkLoggingLister helps list NetworkLoggings.
type NetworkLoggingLister interface {
	// List lists all NetworkLoggings in the indexer.
	List(selector labels.Selector) (ret []*v1alpha1.NetworkLogging, err error)
	// Get retrieves the NetworkLogging from the index for a given name.
	Get(name string) (*v1alpha1.NetworkLogging, error)
	NetworkLoggingListerExpansion
}

// networkLoggingLister implements the NetworkLoggingLister interface.
type networkLoggingLister struct {
	indexer cache.Indexer
}

// NewNetworkLoggingLister returns a new NetworkLoggingLister.
func NewNetworkLoggingLister(indexer cache.Indexer) NetworkLoggingLister {
	return &networkLoggingLister{indexer: indexer}
}

// List lists all NetworkLoggings in the indexer.
func (s *networkLoggingLister) List(selector labels.Selector) (ret []*v1alpha1.NetworkLogging, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha1.NetworkLogging))
	})
	return ret, err
}

// Get retrieves the NetworkLogging from the index for a given name.
func (s *networkLoggingLister) Get(name string) (*v1alpha1.NetworkLogging, error) {
	obj, exists, err := s.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1alpha1.Resource("networklogging"), name)
	}
	return obj.(*v1alpha1.NetworkLogging), nil
}
