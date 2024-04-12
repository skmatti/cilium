(.spec.template.spec.volumes[] | select(.name == "cilium-config-path") | select(.configMap != null) | .configMap.name) |= "cilium-config-modified"
