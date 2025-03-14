package strict

const pingFailJobTemplate = `
---
apiVersion: batch/v1
kind: Job
metadata:
  name: expect-ping-fail
  namespace: %[1]s
spec:
  backoffLimit: 2
  template:
    metadata:
      name: expect-ping-fail-job
    spec:
      containers:
      - name: ping
        image: gcr.io/anthos-networking-ci/toolbox:wora-test
        command: ["/bin/sh", "-c"]
        args:
        - |
          echo "Attempting ping to %[2]s..."
          # Run the ping command
          response=$(ping %[2]s -c 5 -W 2)
          if echo "$response" | grep -q "100%% packet loss"; then
            exit 0
          else
            exit 1
          fi
      nodeSelector:
        kubernetes.io/hostname: %[3]s
      restartPolicy: Never
`

const pingPassJobTemplate = `
---
apiVersion: batch/v1
kind: Job
metadata:
  name: expect-ping-pass
  namespace: %[1]s
  labels:
    networking.private.gdc.goog/infra-access: enabled
spec:
  backoffLimit: 2
  template:
    metadata:
      name: expect-ping-pass-job
      labels:
        networking.private.gdc.goog/infra-access: enabled
    spec:
      containers:
      - name: ping
        image: gcr.io/anthos-networking-ci/toolbox:wora-test
        command: ["/bin/sh", "-c"]
        args:
        - |
          echo "Attempting ping to %[2]s..."
          # Run the ping command
          response=$(ping %[2]s -c 5)
          if echo "$response" | grep -q "5 packets transmitted, 5 received"; then
            exit 0
          else
            exit 1
          fi
      nodeSelector:
        kubernetes.io/hostname: %[3]s
      restartPolicy: Never
`
