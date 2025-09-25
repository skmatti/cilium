package kubevirt

// EnableRoutingOnBootstrap is a shell command string to enable IP forwarding and NAT on the bootstrap node.
const enableRouteOnBootstrap = `sysctl -w net.ipv4.ip_forward=1;
iptables -I FORWARD -j ACCEPT;
iptables -I INPUT -j ACCEPT;
. /etc/os-release;
if [[ $ID == "centos" ]]; then
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE;
else
iptables -t nat -A POSTROUTING -s 10.100.0.0/16 ! -d 10.100.0.0/16 -o eth0 -j MASQUERADE; # This is for the DHCP server VM
fi`
const defaultCloudInit = `#cloud-config
users:
- default
ssh_pwauth: True
chpasswd:
  list: |
    root:google
  expire: False
runcmd:
  - [sed, -i, 's/PasswordAuthentication no/PasswordAuthentication yes/', /etc/ssh/sshd_config]
  - [sed, -i, 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/', /etc/ssh/sshd_config]
  - [service, sshd, restart]
`
const dhcpConfiguratorPodYAML = `
---
apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: default
spec:
  restartPolicy: Never
  dnsPolicy: "None"
  dnsConfig:
    nameservers:
      - "8.8.8.8"
      - "8.8.4.4"
  nodeSelector:
    kubernetes.io/hostname: %s
  containers:
    - name: configurator
      image: ubuntu:20.04
      command:
        - /bin/bash
        - -c
      args:
        - |
          set -ex
          echo "Installing prerequisites inside configurator pod..."
          apt-get update && apt-get install -y openssh-client sshpass netcat
          echo "Prerequisites installed."
          echo "Waiting for VM's SSH service at 10.100.6.5..."
          until nc -z -w 5 10.100.6.5 22; do
            echo "SSH port not ready yet on 10.100.6.5, sleeping 5s...";
            sleep 5;
          done
          echo "SSH port is open. Proceeding with configuration."
          echo "Configuring DHCP server on VM..."
          export SSHPASS='google'
          SSHPASS=$SSHPASS sshpass -e ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@10.100.6.5 << 'EOF'
            set -ex
            echo "STEP 1: Fixing VM DNS configuration..."
            rm -f /etc/resolv.conf
            echo "nameserver 8.8.8.8" > /etc/resolv.conf
            echo "nameserver 8.8.4.4" >> /etc/resolv.conf
            echo "DNS fix complete."
            echo "STEP 2: Updating apt and installing DHCP server..."
            apt-get update -y
            apt-get install -y isc-dhcp-server
            echo "Installation complete."
            echo "STEP 3: Finding and setting listen interface..."
            IFACE_NAME=""
            echo "Waiting for IP 10.100.6.5 to appear on an interface..."
            i=1
            while [ $i -le 12 ]; do # Loop for 60 seconds
              IFACE_NAME=$(ip -o -4 addr show | grep -w '10.100.6.5' | awk '{print $2}' | head -n 1)
              if [ -n "$IFACE_NAME" ]; then
                echo "Found IP 10.100.6.5 on interface $IFACE_NAME."
                break
              fi
              echo "IP 10.100.6.5 not found yet. Retrying in 5s... (Attempt $i/12)"
              sleep 5
              i=$(($i + 1))
            done
            if [ -z "$IFACE_NAME" ]; then
              echo "!!! FATAL: Timed out waiting for interface with IP 10.100.6.5"
              echo "--- DEBUG: Final 'ip -o -4 addr show' output: ---"
              ip -o -4 addr show
              echo "--- DEBUG: End of final IP output ---"
              exit 1
            fi
            echo "Found interface: $IFACE_NAME. Configuring /etc/default/isc-dhcp-server..."
            sed -i 's/^INTERFACESv4=.*/INTERFACESv4="'$IFACE_NAME'"/' /etc/default/isc-dhcp-server
            echo "Interface configuration complete."
            # This uses 'echo' and 'tee' to avoid all YAML/bash indentation bugs.
            echo "STEP 4: Writing main DHCPD config file /etc/dhcp/dhcpd.conf..."
            DHCPD_CONFIG="/etc/dhcp/dhcpd.conf"
            sudo rm -f ${DHCPD_CONFIG}
            echo "default-lease-time 600;" | sudo tee ${DHCPD_CONFIG}
            echo "max-lease-time 7200;" | sudo tee -a ${DHCPD_CONFIG}
            echo "authoritative;" | sudo tee -a ${DHCPD_CONFIG}
            echo "subnet 10.100.0.0 netmask 255.255.248.0 {" | sudo tee -a ${DHCPD_CONFIG}
            echo "  range 10.100.7.100 10.100.7.200;" | sudo tee -a ${DHCPD_CONFIG}
            echo "  option routers 10.100.0.2;" | sudo tee -a ${DHCPD_CONFIG}
            echo "  option subnet-mask 255.255.248.0;" | sudo tee -a ${DHCPD_CONFIG}
            echo "  option domain-name-servers 8.8.8.8, 8.8.4.4;" | sudo tee -a ${DHCPD_CONFIG}
            echo "}" | sudo tee -a ${DHCPD_CONFIG}
            echo "File ${DHCPD_CONFIG} created. Content:"
            cat ${DHCPD_CONFIG}
            echo "STEP 5: Restarting DHCP server with new config..."
            systemctl restart isc-dhcp-server.service
            systemctl status isc-dhcp-server.service
            echo "DHCP server setup script finished successfully."
          EOF
`
const nfsController = `
---
kind: Deployment
apiVersion: apps/v1
metadata:
  name: csi-nfs-controller
  namespace: kube-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app: csi-nfs-controller
  template:
    metadata:
      labels:
        app: csi-nfs-controller
    spec:
      dnsPolicy: ClusterFirstWithHostNet
      serviceAccountName: csi-nfs-controller-sa
      nodeSelector:
        kubernetes.io/os: linux
        node-role.kubernetes.io/control-plane: ""
      priorityClassName: system-cluster-critical
      tolerations:
        - operator: "Exists"
      containers:
        - name: csi-provisioner
          image: k8s.gcr.io/sig-storage/csi-provisioner:v3.1.0
          args:
            - "-v=2"
            - "--csi-address=$(ADDRESS)"
            - "--leader-election"
          env:
            - name: ADDRESS
              value: /csi/csi.sock
          volumeMounts:
            - mountPath: /csi
              name: socket-dir
          resources:
            limits:
              memory: 400Mi
            requests:
              cpu: 10m
              memory: 20Mi
        - name: liveness-probe
          image: k8s.gcr.io/sig-storage/livenessprobe:v2.6.0
          args:
            - --csi-address=/csi/csi.sock
            - --probe-timeout=3s
            - --health-port=29652
            - --v=2
          volumeMounts:
            - name: socket-dir
              mountPath: /csi
          resources:
            limits:
              memory: 100Mi
            requests:
              cpu: 10m
              memory: 20Mi
        - name: nfs
          image: k8s.gcr.io/sig-storage/nfsplugin:v3.1.0
          securityContext:
            privileged: true
            capabilities:
              add: ["SYS_ADMIN"]
            allowPrivilegeEscalation: true
          imagePullPolicy: IfNotPresent
          args:
            - "-v=5"
            - "--nodeid=$(NODE_ID)"
            - "--endpoint=$(CSI_ENDPOINT)"
          env:
            - name: NODE_ID
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
            - name: CSI_ENDPOINT
              value: unix:///csi/csi.sock
          ports:
            - containerPort: 29652
              name: healthz
              protocol: TCP
          livenessProbe:
            failureThreshold: 5
            httpGet:
              path: /healthz
              port: healthz
            initialDelaySeconds: 30
            timeoutSeconds: 10
            periodSeconds: 30
          volumeMounts:
            - name: pods-mount-dir
              mountPath: /var/lib/kubelet/pods
              mountPropagation: "Bidirectional"
            - mountPath: /csi
              name: socket-dir
          resources:
            limits:
              memory: 200Mi
            requests:
              cpu: 10m
              memory: 20Mi
      volumes:
        - name: pods-mount-dir
          hostPath:
            path: /var/lib/kubelet/pods
            type: Directory
        - name: socket-dir
          emptyDir: {}
`
const nfsNode = `
---
kind: DaemonSet
apiVersion: apps/v1
metadata:
  name: csi-nfs-node
  namespace: kube-system
spec:
  updateStrategy:
    rollingUpdate:
      maxUnavailable: 1
    type: RollingUpdate
  selector:
    matchLabels:
      app: csi-nfs-node
  template:
    metadata:
      labels:
        app: csi-nfs-node
    spec:
      hostNetwork: true  # original nfs connection would be broken without hostNetwork setting
      dnsPolicy: ClusterFirstWithHostNet
      nodeSelector:
        kubernetes.io/os: linux
        node-role.kubernetes.io/worker: ""
      tolerations:
        - operator: "Exists"
      containers:
        - name: liveness-probe
          image: k8s.gcr.io/sig-storage/livenessprobe:v2.6.0
          args:
            - --csi-address=/csi/csi.sock
            - --probe-timeout=3s
            - --health-port=29653
            - --v=2
          volumeMounts:
            - name: socket-dir
              mountPath: /csi
          resources:
            limits:
              memory: 100Mi
            requests:
              cpu: 10m
              memory: 20Mi
        - name: node-driver-registrar
          image: k8s.gcr.io/sig-storage/csi-node-driver-registrar:v2.5.0
          args:
            - --v=2
            - --csi-address=/csi/csi.sock
            - --kubelet-registration-path=$(DRIVER_REG_SOCK_PATH)
          livenessProbe:
            exec:
              command:
                - /csi-node-driver-registrar
                - --kubelet-registration-path=$(DRIVER_REG_SOCK_PATH)
                - --mode=kubelet-registration-probe
            initialDelaySeconds: 30
            timeoutSeconds: 15
          env:
            - name: DRIVER_REG_SOCK_PATH
              value: /var/lib/kubelet/plugins/csi-nfsplugin/csi.sock
            - name: KUBE_NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
          volumeMounts:
            - name: socket-dir
              mountPath: /csi
            - name: registration-dir
              mountPath: /registration
          resources:
            limits:
              memory: 100Mi
            requests:
              cpu: 10m
              memory: 20Mi
        - name: nfs
          securityContext:
            privileged: true
            capabilities:
              add: ["SYS_ADMIN"]
            allowPrivilegeEscalation: true
          image: k8s.gcr.io/sig-storage/nfsplugin:v3.1.0
          args:
            - "-v=5"
            - "--nodeid=$(NODE_ID)"
            - "--endpoint=$(CSI_ENDPOINT)"
          env:
            - name: NODE_ID
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
            - name: CSI_ENDPOINT
              value: unix:///csi/csi.sock
          ports:
            - containerPort: 29653
              name: healthz
              protocol: TCP
          livenessProbe:
            failureThreshold: 5
            httpGet:
              path: /healthz
              port: healthz
            initialDelaySeconds: 30
            timeoutSeconds: 10
            periodSeconds: 30
          imagePullPolicy: "IfNotPresent"
          volumeMounts:
            - name: socket-dir
              mountPath: /csi
            - name: pods-mount-dir
              mountPath: /var/lib/kubelet/pods
              mountPropagation: "Bidirectional"
          resources:
            limits:
              memory: 300Mi
            requests:
              cpu: 10m
              memory: 20Mi
      volumes:
        - name: socket-dir
          hostPath:
            path: /var/lib/kubelet/plugins/csi-nfsplugin
            type: DirectoryOrCreate
        - name: pods-mount-dir
          hostPath:
            path: /var/lib/kubelet/pods
            type: Directory
        - hostPath:
            path: /var/lib/kubelet/plugins_registry
            type: Directory
          name: registration-dir
`
const csiDriver = `
---
apiVersion: storage.k8s.io/v1
kind: CSIDriver
metadata:
  name: nfs.csi.k8s.io
  namespace: default
spec:
  attachRequired: false
  volumeLifecycleModes:
    - Persistent
    - Ephemeral
`
const nfsServer = `
---
apiVersion: v1
kind: Service
metadata:
  name: nfs-server
  namespace: default
spec:
  selector:
    app: nfs-server
  ports:
    - name: nfs
      port: 2049
      protocol: TCP
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: nfs-server
  namespace: default
spec:
  selector:
    matchLabels:
      app: nfs-server
  serviceName: "nfs-server"
  replicas: 1
  template:
    metadata:
      labels:
        app: nfs-server
    spec:
      containers:
      - name: nfs-server
        image: k8s.gcr.io/volume-nfs:0.8
        ports:
          - name: nfs
            containerPort: 2049
        securityContext:
          privileged: true
        volumeMounts:
          - mountPath: /exports
            name: nfs-data
  volumeClaimTemplates:
  - metadata:
      name: nfs-data
    spec:
      accessModes: [ "ReadWriteOnce" ]
      storageClassName: local-shared # Use your default StorageClass for the underlying disk
      resources:
        requests:
          storage: 10Gi
`
const rbaccsiNfscontroller = `
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: csi-nfs-controller-sa
  namespace: kube-system
---
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: nfs-external-provisioner-role
  namespace: default
rules:
  - apiGroups: [""]
    resources: ["persistentvolumes"]
    verbs: ["get", "list", "watch", "create", "delete"]
  - apiGroups: [""]
    resources: ["persistentvolumeclaims"]
    verbs: ["get", "list", "watch", "update"]
  - apiGroups: ["storage.k8s.io"]
    resources: ["storageclasses"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["get", "list", "watch", "create", "update", "patch"]
  - apiGroups: ["storage.k8s.io"]
    resources: ["csinodes"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["coordination.k8s.io"]
    resources: ["leases"]
    verbs: ["get", "list", "watch", "create", "update", "patch"]
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get"]
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: nfs-csi-provisioner-binding
  namespace: default
subjects:
  - kind: ServiceAccount
    name: csi-nfs-controller-sa
    namespace: kube-system
roleRef:
  kind: ClusterRole
  name: nfs-external-provisioner-role
  apiGroup: rbac.authorization.k8s.io
`
const unMountsecrets = `
---
apiVersion: v1
kind: Secret
metadata:
  name: nfs-unmount-options
  namespace: default
data:
  # mountoptions: port=42049
  # (background: b/230050129)
  mountoptions: cG9ydD0yMDQ5
type: Opaque
`
const nfsStorageClass = `
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: nfs-csi
provisioner: nfs.csi.k8s.io
parameters:
  server: nfs-server.default.svc.cluster.local
  share: "/"
  csi.storage.k8s.io/provisioner-secret-name: "nfs-unmount-options"
  csi.storage.k8s.io/provisioner-secret-namespace: "default"
reclaimPolicy: Delete
volumeBindingMode: Immediate
mountOptions:
  - "nconnect=8"
  - "hard"
  - "nfsvers=4.1"
  - "port=2049"
`
