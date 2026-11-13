package agent

import (
	"github.com/antoniomika/lend/internal/approval"
	"github.com/antoniomika/lend/internal/caller"
	"github.com/antoniomika/lend/internal/sshagent"
)

type connectionInfo struct {
	id       string
	peer     *caller.Peer
	bindings []approval.SSHBinding
	omitted  int
}

func (i *connectionInfo) bind(binding sshagent.Binding) {
	if len(i.bindings) == 8 {
		i.omitted++
		return
	}
	i.bindings = append(i.bindings, approval.SSHBinding{Fingerprint: binding.Fingerprint, Forwarding: binding.Forwarding})
}

func (i connectionInfo) summary(summary approval.Summary) approval.Summary {
	summary.Peer = i.peer
	summary.Bindings = append([]approval.SSHBinding(nil), i.bindings...)
	summary.OmittedBindings = i.omitted
	return summary
}
