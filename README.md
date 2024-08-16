# Keyauth-Protected-App-Go
Keyauth-Protected-App-Go is a Go-based application that integrates with the KeyAuth API to provide secure user authentication. It comes with built-in anti-debugging and anti-DLL injection features to protect against reverse engineering and unauthorized modifications.

## Security Features

## Anti-Debugging Features
  - **Debugger Presence**: Detects if a debugger is attached using the `IsDebuggerPresent` check and terminates the application if detected.
  - **Remote Debuggers**: Identifies and terminates the application if a remote debugger is found.
  - **Internet Connection Check**: Ensures the application runs only with an active internet connection, preventing offline debugging attempts.
  - **Parent Process Anti-Debugging**: Detects suspicious parent processes that may indicate debugging or sandboxing activity.
  - **Blacklisted Windows**: Prevents execution if known blacklisted windows associated with debuggers are present.

## Anti-Dll-Injection
- Protects against third-party DLL injection by configuring process mitigation policies. This feature prevents unauthorized DLLs from being injected into the application, ensuring the integrity of the application's runtime environment.

# To-Do:
- Add Patch for LoadLibraryA/W.
- ACG (dyncode)
# Credit:
- https://github.com/KeyAuth/KeyAuth-Go-Example
