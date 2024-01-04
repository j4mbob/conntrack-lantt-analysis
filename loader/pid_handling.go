package loader

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
)

func implementPID(pidFile string) {
	if checkPID(pidFile) {
		fmt.Printf("Another instance of lanRTT is already running. Exiting.\n")
		os.Exit(1)
	}

	err := writePID(pidFile)
	if err != nil {
		fmt.Printf("Unable to write PID file: %s\n", err)
		os.Exit(1)
	}

}

func writePID(pidFile string) error {
	pid := []byte(strconv.Itoa(os.Getpid()) + "\n")
	return os.WriteFile(pidFile, pid, 0644)
}

func checkPID(pidFile string) bool {
	pidData, err := os.ReadFile(pidFile)
	if err != nil {
		return false
	}

	pid, err := strconv.Atoi(string(pidData))
	if err != nil {
		fmt.Printf("Invalid PID in PID file: %s\n", pidData)
		os.Exit(1)
		return false
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	err = process.Signal(syscall.Signal(0))
	return err == nil
}

func CleanUp(pidFile string) {

	err := os.Remove(pidFile)
	if err != nil {
		fmt.Printf("error removing PID file: %v\n", err)
	}
	fmt.Println("exiting...")
	os.Exit(1)
}
