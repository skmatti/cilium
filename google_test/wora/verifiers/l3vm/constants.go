package l3vm

const ipamTemplate = `
---
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  namespace: kube-system
  name: metallb-ipam-%[1]s
  annotations:
    networking.gke.io/network: %[1]s
spec:
  addresses:
  - %[2]s
  autoAssign: true
  avoidBuggyIPs: false
`
