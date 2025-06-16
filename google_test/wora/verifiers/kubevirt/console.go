package kubevirt

import (
	"fmt"
	"io"
	"regexp"
	"strings"
	"time" // Do not use pkg/time in test code.

	. "github.com/onsi/ginkgo/v2"

	expect "github.com/google/goexpect"
	virtv1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"
	kubevirtcorev1 "kubevirt.io/client-go/kubevirt/typed/core/v1"

	klog "gke-internal.googlesource.com/syllogi/sanitized-klog/third_party/klogv2"
)

// NewExpecter will connect to an already logged in VMI console and return the generated expecter it will wait `timeout` for the connection.
func NewExpecter(virtCli kubecli.KubevirtClient, vmi *virtv1.VirtualMachineInstance, timeout time.Duration, opts ...expect.Option) (expect.Expecter, <-chan error, error) {
	vmiReader, vmiWriter := io.Pipe()
	expecterReader, expecterWriter := io.Pipe()
	resCh := make(chan error)

	startTime := time.Now()
	con, err := virtCli.VirtualMachineInstance(vmi.Namespace).SerialConsole(vmi.Name, &kubevirtcorev1.SerialConsoleOptions{ConnectionTimeout: timeout})
	if err != nil {
		return nil, nil, err
	}
	timeout = time.Since(startTime)

	go func() {
		resCh <- con.Stream(kubevirtcorev1.StreamOptions{
			In:  vmiReader,
			Out: expecterWriter,
		})
	}()

	opts = append(opts, expect.SendTimeout(timeout))
	opts = append(opts, expect.Verbose(true))
	opts = append(opts, expect.VerboseWriter(GinkgoWriter))
	return expect.SpawnGeneric(&expect.GenOptions{
		In:  vmiWriter,
		Out: expecterReader,
		Wait: func() error {
			return <-resCh
		},
		Close: func() error {
			expecterWriter.Close()
			vmiReader.Close()
			return nil
		},
		Check: func() bool { return true },
	}, timeout, opts...)
}

// ExpectBatchWithValidatedSend adds the expect.BSnd command to the exect.BExp expression.
// It is done to make sure the match was found in the result of the expect.BSnd
// command and not in a leftover that wasn't removed from the buffer.
// NOTE: the method contains the following limitations:
//   - Use of `BatchSwitchCase`
//   - Multiline commands
//   - No more than one sequential send or receive
func ExpectBatchWithValidatedSend(expecter expect.Expecter, batch []expect.Batcher, timeout time.Duration) ([]expect.BatchRes, error) {
	sendFlag := false
	expectFlag := false
	previousSend := ""

	if len(batch) < 2 {
		return nil, fmt.Errorf("ExpectBatchWithValidatedSend requires at least 2 batchers, supplied %v", batch)
	}

	for i, batcher := range batch {
		switch batcher.Cmd() {
		case expect.BatchExpect:
			if expectFlag {
				return nil, fmt.Errorf("Two sequential expect.BExp are not allowed")
			}
			expectFlag = true
			sendFlag = false
			if _, ok := batch[i].(*expect.BExp); !ok {
				return nil, fmt.Errorf("ExpectBatchWithValidatedSend support only expect of type BExp")
			}
			bExp, _ := batch[i].(*expect.BExp)
			previousSend := regexp.QuoteMeta(previousSend)

			// Remove the \n since it is translated by the console to \r\n.
			previousSend = strings.TrimSuffix(previousSend, "\n")
			bExp.R = fmt.Sprintf("%s%s%s", previousSend, "((?s).*)", bExp.R)
		case expect.BatchSend:
			if sendFlag {
				return nil, fmt.Errorf("Two sequential expect.BSend are not allowed")
			}
			sendFlag = true
			expectFlag = false
			previousSend = batcher.Arg()
		case expect.BatchSwitchCase:
			return nil, fmt.Errorf("ExpectBatchWithValidatedSend doesn't support BatchSwitchCase")
		default:
			return nil, fmt.Errorf("Unknown command: ExpectBatchWithValidatedSend supports only BatchExpect and BatchSend")
		}
	}

	res, err := expecter.ExpectBatch(batch, timeout)
	return res, err
}

func expectConsoleOutput(virtclient kubecli.KubevirtClient, vmi *virtv1.VirtualMachineInstance, cmd, expected string, timeout time.Duration) error {
	expecter, _, err := NewExpecter(virtclient, vmi, 30*time.Second)
	if err != nil {
		return err
	}
	defer expecter.Close()

	expects := []expect.Batcher{
		&expect.BSnd{S: cmd},
		&expect.BExp{R: expected},
	}
	resp, err := ExpectBatchWithValidatedSend(expecter, expects, timeout)
	klog.Infof("Console output for VM %s: %v", vmi.Name, resp)
	if err != nil {
		return err
	}
	return err
}

// consoleLogin logins the VM through console. It expects the username and password of the VM to be
// "root" and "google", respectively. It assumes the VM is default namespace.
func consoleLogin(virtClient kubecli.KubevirtClient, vmi *virtv1.VirtualMachineInstance) error {
	err := expectConsoleOutput(virtClient, vmi, "\n", "login", defaultConsoleRespDuration)
	if err != nil {
		return fmt.Errorf("console response does not contain \"login\": %w", err)
	}
	_ = expectConsoleOutput(virtClient, vmi, "\nroot\n", "", cmdConsoleRespDuration)
	_ = expectConsoleOutput(virtClient, vmi, "google\n", "", cmdConsoleRespDuration)
	err = expectConsoleOutput(virtClient, vmi, "\n", vmi.Name, cmdConsoleRespDuration)
	if err != nil {
		return fmt.Errorf("console response does not contain %s: %w", vmi.Name, err)
	}
	return nil
}

func consoleExec(virtClient kubecli.KubevirtClient, vmi *virtv1.VirtualMachineInstance, cmd string, expectResponse string) error {
	err := expectConsoleOutput(virtClient, vmi, cmd, expectResponse, defaultConsoleRespDuration)
	if err != nil {
		return fmt.Errorf("console response does not contain expectResponse %s: %w", expectResponse, err)
	}
	return nil
}
