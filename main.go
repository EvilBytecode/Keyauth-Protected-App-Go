package main

import (
	KeyAuthApp "Keyauth-Protected-App/Keyauth"
	"Keyauth-Protected-App/anti-debug"
	"fmt"
	"os"
	"time"
)

func Input(message string) string {
	fmt.Print(message)

	var input string
	fmt.Scanln(&input)
	return input
}

// initKeyAuthApp initializes the KeyAuth API.
func initKeyAuthApp() {
	KeyAuthApp.Api(
		"",    // -- Application Name
		"",      // -- Owner ID
		"",                // -- Application Secret
		"1.0",             // -- Application Version (v1.0 is normal)
		"",                // -- Token Path (PUT NULL OR LEAVE BLANK IF YOU DON'T WANT TO USE TOKEN SYSTEM)
	)
}

// Login contains the login logic for the application.
func Login() {
	// Initialize the KeyAuth API
	initKeyAuthApp()

	license := Input("Input license: ")
	KeyAuthApp.License(license)

    // Related to Printing user data which isnt needed.
    /*
    fmt.Println("\nUser Data:")
    fmt.Println("   Username: ", KeyAuthApp.Username)
    fmt.Println("   IP Address: ", KeyAuthApp.IP)
    fmt.Println("   HWID: ", KeyAuthApp.HWID)
    fmt.Println("   Created At: ", KeyAuthApp.CreatedDate)
    fmt.Println("   Last Login At: ", KeyAuthApp.LastLogin)
    fmt.Println("   Subscription: ", KeyAuthApp.Subscription)
    */

	fmt.Println("\nSuccessfully logged in lol")
	time.Sleep(400 * time.Second)
	os.Exit(0)
}

func main() {
	go anti_debug.InitAntiDbg()
    // btw there are more choices like user:pass and more, for that check out : https://github.com/KeyAuth/KeyAuth-Go-Example/blob/main/main.go
	Login()
}
