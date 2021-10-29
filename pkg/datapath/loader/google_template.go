package loader

import "github.com/cilium/cilium/pkg/datapath"

const (
	templatePodStackRedirectIfIndex = int(0xdeadbeef)
)

// GetPodStackRedirectIfindex returns a filler podStackRedirectIfindex
// compile-time/which/will be later substituted in the ELF.
func (t *templateCfg) GetPodStackRedirectIfindex() int {
	return templatePodStackRedirectIfIndex
}

// multiNicElfVariableSubstitutions fills in Elf substitutions in the template,
// pertaining to Multi-nic endpoints.
func multiNicElfVariableSubstitutions(ep datapath.Endpoint,
	result map[string]uint32) {
	if !ep.IsMultiNIC() {
		return
	}
	result["POD_STACK_REDIRECT_IFINDEX"] =
		uint32(ep.GetPodStackRedirectIfindex())
}
