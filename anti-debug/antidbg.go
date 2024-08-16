package anti_debug

import (
	"os"
	// AntiDebug
	"github.com/EvilBytecode/GoDefender/AntiDebug/InternetCheck"
	"github.com/EvilBytecode/GoDefender/AntiDebug/IsDebuggerPresent"
	"github.com/EvilBytecode/GoDefender/AntiDebug/ParentAntiDebug"
	"github.com/EvilBytecode/GoDefender/AntiDebug/RemoteDebugger"
)

func InitAntiDbg() {
	ConfigureProcessMitigationPolicy()
	for {
		anti_dbg_main()
	}
}

func anti_dbg_main() {
	CheckBlacklistedWindows()
	if isDebuggerPresentResult := IsDebuggerPresent.IsDebuggerPresent1(); isDebuggerPresentResult {
		os.Exit(-1)
	}

	if remoteDebuggerDetected, _ := RemoteDebugger.RemoteDebugger(); remoteDebuggerDetected {
		os.Exit(-1)
	}

	if connected, _ := InternetCheck.CheckConnection(); !connected {
		os.Exit(-1)
	}

	if parentAntiDebugResult := ParentAntiDebug.ParentAntiDebug(); parentAntiDebugResult {
		os.Exit(-1)
	}

}
