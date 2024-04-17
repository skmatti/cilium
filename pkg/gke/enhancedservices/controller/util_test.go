package controller

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"gke-internal.googlesource.com/kon/pkg/model"
)

func TestCompareEndpointSubset(t *testing.T) {
	testCases := []struct {
		name            string
		old             *model.EndpointSubset
		new             *model.EndpointSubset
		expectedAdded   []model.Endpoint
		expectedDeleted []model.Endpoint
	}{
		{
			name: "No changes",
			old: &model.EndpointSubset{
				XDSCluster: "cluster1",
				Endpoints: []model.Endpoint{
					{Ready: true, Address: model.Address{IP: "10.0.0.1", Zone: "us-east", Port: 8080}},
				},
			},
			new: &model.EndpointSubset{
				XDSCluster: "cluster1",
				Endpoints: []model.Endpoint{
					{Ready: true, Address: model.Address{IP: "10.0.0.1", Zone: "us-east", Port: 8080}},
				},
			},
			expectedAdded:   nil,
			expectedDeleted: nil,
		},
		{
			name: "Addition",
			old: &model.EndpointSubset{
				XDSCluster: "cluster1",
				Endpoints: []model.Endpoint{
					{Ready: true, Address: model.Address{IP: "10.0.0.1", Zone: "us-east", Port: 8080}},
				},
			},
			new: &model.EndpointSubset{
				XDSCluster: "cluster1",
				Endpoints: []model.Endpoint{
					{Ready: true, Address: model.Address{IP: "10.0.0.1", Zone: "us-east", Port: 8080}},
					{Ready: false, Address: model.Address{IP: "10.0.0.2", Zone: "us-west", Port: 80}},
				},
			},
			expectedAdded: []model.Endpoint{
				{Ready: false, Address: model.Address{IP: "10.0.0.2", Zone: "us-west", Port: 80}},
			},
			expectedDeleted: nil,
		},
		{
			name: "Deletion",
			old: &model.EndpointSubset{
				XDSCluster: "cluster1",
				Endpoints: []model.Endpoint{
					{Ready: true, Address: model.Address{IP: "10.0.0.1", Zone: "us-east", Port: 8080}},
					{Ready: false, Address: model.Address{IP: "10.0.0.2", Zone: "us-west", Port: 80}},
				},
			},
			new: &model.EndpointSubset{
				XDSCluster: "cluster1",
				Endpoints: []model.Endpoint{
					{Ready: true, Address: model.Address{IP: "10.0.0.1", Zone: "us-east", Port: 8080}},
				},
			},
			expectedAdded: nil,
			expectedDeleted: []model.Endpoint{
				{Ready: false, Address: model.Address{IP: "10.0.0.2", Zone: "us-west", Port: 80}},
			},
		},
		{
			name: "Addition and Deletion",
			old: &model.EndpointSubset{
				XDSCluster: "cluster1",
				Endpoints: []model.Endpoint{
					{Ready: true, Address: model.Address{IP: "10.0.0.1", Zone: "us-east", Port: 8080}},
					{Ready: false, Address: model.Address{IP: "10.0.0.2", Zone: "us-west", Port: 80}},
				},
			},
			new: &model.EndpointSubset{
				XDSCluster: "cluster1",
				Endpoints: []model.Endpoint{
					{Ready: false, Address: model.Address{IP: "10.0.0.2", Zone: "us-west", Port: 80}},     // Same address
					{Ready: true, Address: model.Address{IP: "10.0.0.3", Zone: "eu-central", Port: 3000}}, // New address
				},
			},
			expectedAdded: []model.Endpoint{
				{Ready: true, Address: model.Address{IP: "10.0.0.3", Zone: "eu-central", Port: 3000}},
			},
			expectedDeleted: []model.Endpoint{
				{Ready: true, Address: model.Address{IP: "10.0.0.1", Zone: "us-east", Port: 8080}},
			},
		},
		{
			name: "Old subset is nil",
			old:  nil,
			new: &model.EndpointSubset{
				XDSCluster: "cluster1",
				Endpoints: []model.Endpoint{
					{Ready: true, Address: model.Address{IP: "10.0.0.1", Zone: "us-east", Port: 8080}},
				},
			},
			expectedAdded: []model.Endpoint{
				{Ready: true, Address: model.Address{IP: "10.0.0.1", Zone: "us-east", Port: 8080}},
			},
			expectedDeleted: nil,
		},
		{
			name: "New subset is nil",
			old: &model.EndpointSubset{
				XDSCluster: "cluster1",
				Endpoints: []model.Endpoint{
					{Ready: true, Address: model.Address{IP: "10.0.0.1", Zone: "us-east", Port: 8080}},
				},
			},
			new:           nil,
			expectedAdded: nil,
			expectedDeleted: []model.Endpoint{
				{Ready: true, Address: model.Address{IP: "10.0.0.1", Zone: "us-east", Port: 8080}},
			},
		},
		{
			name:            "Both subsets are nil",
			old:             nil,
			new:             nil,
			expectedAdded:   nil,
			expectedDeleted: nil,
		},
		{
			name: "Update",
			old: &model.EndpointSubset{
				XDSCluster: "cluster1",
				Endpoints: []model.Endpoint{
					{Ready: true, Address: model.Address{IP: "10.0.0.1", Zone: "us-east", Port: 8080}},
				},
			},
			new: &model.EndpointSubset{
				XDSCluster: "cluster1",
				Endpoints: []model.Endpoint{
					{Ready: false, Address: model.Address{IP: "10.0.0.1", Zone: "us-east", Port: 8080}},
				},
			},
			expectedAdded: []model.Endpoint{
				{Ready: false, Address: model.Address{IP: "10.0.0.1", Zone: "us-east", Port: 8080}},
			},
			expectedDeleted: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			upserted, deleted := compareEndpointSubset(tc.old, tc.new)

			if diff := cmp.Diff(tc.expectedAdded, upserted); diff != "" {
				t.Errorf("Upserted mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.expectedDeleted, deleted); diff != "" {
				t.Errorf("Deleted mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
