.metadata.name="anetd-modified" |
del(.spec.template.spec.nodeSelector["networking.gke.io/select-nothing"]) |
del(.metadata.labels["addonmanager.kubernetes.io/mode"]) |
del(.status)
