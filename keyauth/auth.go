package keyauth

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"os/exec"
	"path/filepath"

	"github.com/google/uuid"
)

var (
    APIUrl           string = "https://keyauth.win/api/1.2/"
    NumUsers         string
    NumOnlineUsers   string
    NumKeys          string
    CustomerPanelURL string
    SessionID        string = "lol"
)

var (
    Name          string
    OwnerID       string
    Secret        string
    Version       string
	TokenPath	  string
    Username      string
    IP            string
    HWID          string
    CreatedDate   string
    Expires       string
    LastLogin     string
    Subscription  string
    Subscriptions string
    Initialized   bool
	EncKey        string
)

func Api(name, ownerid, secret, version, path string) {
    if name == "" || ownerid == "" || secret == "" || version == "" || len(ownerid) != 10 || len(secret) != 64 {
        fmt.Println("Application not set up properly.")
        time.Sleep(3 * time.Second)
        os.Exit(1)
    }

    Name = name
    OwnerID = ownerid
    Secret = secret
    Version = version
	TokenPath = path
	if path == "null" { TokenPath = "" }

    Init()
}

func Init() {
	if SessionID != "lol" {
		fmt.Println("You have already initialized this application.")
		time.Sleep(3 * time.Second)
		os.Exit(1)
	}

	sentKey := uuid.New().String()[:16]
	EncKey = sentKey + "-" + Secret
	
	postData := map[string]string{
		"type":    "init",
		"ver":     Version,
		"hash":    checkSum(filepath.Base(os.Args[0])),
		"enckey":  sentKey,
		"name":    Name,
		"ownerid": OwnerID,
	}	

	if TokenPath != "" {
		token, err := ioutil.ReadFile(TokenPath)
		if err != nil {
			fmt.Println("Error reading token file: " + err.Error())
		}
		postData["token"] = string(token)
		postData["thash"] = tokenHash(TokenPath)
	}

	response := doRequest(postData);

	if response == "KeyAuth_Invalid" {
		fmt.Println("The application does not exist.")
		time.Sleep(3 * time.Second)
		os.Exit(1)
	}

	var jsonResponse map[string]interface{}
	if err := json.Unmarshal([]byte(response), &jsonResponse); err != nil {
		fmt.Println("Error decoding JSON response: " + err.Error())
		time.Sleep(3 * time.Second)
		os.Exit(1)
	}

	if jsonResponse["message"] == "invalidver" {
		if jsonResponse["download"] != "" {
			fmt.Println("New application version found! Downloading...")
			downloadLink := jsonResponse["download"].(string)
			openUrl(downloadLink)
			time.Sleep(3 * time.Second)
			os.Exit(1)
		} else {
			fmt.Println("Invalid application version, contact the owner to add the download link for the latest app version")
			time.Sleep(3 * time.Second)
			os.Exit(1)
		}
	}

	if !jsonResponse["success"].(bool) {
		fmt.Println(jsonResponse["message"].(string))
		time.Sleep(3 * time.Second)
		os.Exit(1)
	}

	SessionID = jsonResponse["sessionid"].(string)
	Initialized = true

	if jsonResponse["newSession"].(bool) {
		time.Sleep(100 * time.Millisecond)
	}
}

func Register(user, password, license string) {
	CheckInit()

	hwid := GetHWID()

    postData := map[string]string{
        "type":      "register",
        "username":  user,
        "pass":      password,
        "key":       license,
        "hwid":      hwid,
        "sessionid": SessionID,
        "name":      Name,
        "ownerid":   OwnerID,
    }

	response := doRequest(postData)

    var jsonResponse map[string]interface{}
    if err := json.Unmarshal([]byte(response), &jsonResponse); err != nil {
		fmt.Println("Error decoding JSON response: " + err.Error())
        time.Sleep(3 * time.Second)
        os.Exit(1)
    }

    if jsonResponse["success"].(bool) {
		fmt.Println(jsonResponse["message"].(string))
        LoadUserData(jsonResponse["info"])
    } else {
		fmt.Println(jsonResponse["message"].(string))
        time.Sleep(3 * time.Second)
        os.Exit(1)
    }
}

func Login(user, password string) {
    CheckInit()

    hwid := GetHWID()

    postData := map[string]string{
        "type":      "login",
        "username":  user,
        "pass":      password,
        "hwid":      hwid,
        "sessionid": SessionID,
        "name":      Name,
        "ownerid":   OwnerID,
    }

    response := doRequest(postData)

    var jsonResponse map[string]interface{}
    if err := json.Unmarshal([]byte(response), &jsonResponse); err != nil {
		fmt.Println("Error decoding JSON response: " + err.Error())
        time.Sleep(3 * time.Second)
        os.Exit(1)
    }

    if jsonResponse["success"].(bool) {
		fmt.Println(jsonResponse["message"].(string))
        LoadUserData(jsonResponse["info"])
    } else {
		fmt.Println(jsonResponse["message"].(string))
        time.Sleep(3 * time.Second)
        os.Exit(1)
    }
}

func Forgot(user, email string) {
    CheckInit()

    postData := map[string]string{
        "type":      "forgot",
        "username":  user,
        "email":     email,
        "sessionid": SessionID,
        "name":      Name,
        "ownerid":   OwnerID,
    }

    response := doRequest(postData)

    var jsonResponse map[string]interface{}
    if err := json.Unmarshal([]byte(response), &jsonResponse); err != nil {
		fmt.Println("Error decoding JSON response: " + err.Error())
        time.Sleep(3 * time.Second)
        os.Exit(1)
    }

    if jsonResponse["success"].(bool) {
		fmt.Println(jsonResponse["message"].(string))
        LoadUserData(jsonResponse["info"])
    } else {
		fmt.Println(jsonResponse["message"].(string))
        time.Sleep(3 * time.Second)
        os.Exit(1)
    }
}

func Upgrade(user, license string) {
	CheckInit()

	postData := map[string]string{
		"type":      "upgrade",
		"username":  user,
		"key":       license,
		"sessionid": SessionID,
		"name":      Name,
		"ownerid":   OwnerID,
	}

	response := doRequest(postData)

    var jsonResponse map[string]interface{}
    if err := json.Unmarshal([]byte(response), &jsonResponse); err != nil {
		fmt.Println("Error decoding JSON response: " + err.Error())
        time.Sleep(3 * time.Second)
        os.Exit(1)
    }

    if jsonResponse["success"].(bool) {
		fmt.Println(jsonResponse["message"].(string))
		fmt.Println("Please restart the application and login again to see the changes.")
        time.Sleep(3 * time.Second)
        os.Exit(1)
    } else {
		fmt.Println(jsonResponse["message"].(string))
        time.Sleep(3 * time.Second)
        os.Exit(1)
    }
}

func License(key string) {
	CheckInit()

	hwid := GetHWID()

	postData := map[string]string{
		"type":      "license",
		"key":       key,
		"hwid":      hwid,
		"sessionid": SessionID,
		"name":      Name,
		"ownerid":   OwnerID,
	}

	response := doRequest(postData)

	var jsonResponse map[string]interface{}
	if err := json.Unmarshal([]byte(response), &jsonResponse); err != nil {
		fmt.Println("Error decoding JSON response: " + err.Error())
		time.Sleep(3 * time.Second)
		os.Exit(1)
	}

	if jsonResponse["success"].(bool) {
		LoadUserData(jsonResponse["info"])
		fmt.Println(jsonResponse["message"].(string))
	} else {
		fmt.Println(jsonResponse["message"].(string))
		time.Sleep(3 * time.Second)
		os.Exit(1)
	}
}

func Var(name string) string {
	CheckInit()

	postData := map[string]string{
		"type":      "var",
		"varid":     name,
		"sessionid": SessionID,
		"name":      Name,
		"ownerid":   OwnerID,
	}

	response := doRequest(postData)

	var jsonResponse map[string]interface{}
	if err := json.Unmarshal([]byte(response), &jsonResponse); err != nil {
		fmt.Println("Error decoding JSON response: " + err.Error())
		time.Sleep(3 * time.Second)
		os.Exit(1)
	}

	if jsonResponse["success"].(bool) {
		return jsonResponse["message"].(string)
	} else {
		fmt.Println(jsonResponse["message"].(string))
		time.Sleep(3 * time.Second)
		os.Exit(1)
	}

    return ""
}

func GetVar(varName string) string {
	CheckInit()

	postData := map[string]string{
		"type":      "getvar",
		"var":       varName,
		"sessionid": SessionID,
		"name":      Name,
		"ownerid":   OwnerID,
	}

	response := doRequest(postData)

	var jsonResponse map[string]interface{}
	if err := json.Unmarshal([]byte(response), &jsonResponse); err != nil {
		fmt.Println("Error decoding JSON response: " + err.Error())
		time.Sleep(3 * time.Second)
		os.Exit(1)
	}

	if jsonResponse["success"].(bool) {
		return jsonResponse["response"].(string)
	} else {
		fmt.Println("NOTE: This is commonly misunderstood. This is for user variables, not the normal variables.")
		fmt.Println("Use KeyAuthApp.var(\"%s\") for normal variables." + varName)
		fmt.Println(jsonResponse["message"].(string))
		time.Sleep(3 * time.Second)
		os.Exit(1)
	}

	return ""
}

func SetVar(varName, varData string) bool {
	CheckInit()

	postData := map[string]string{
		"type":      "setvar",
		"var":       varName,
		"data":      varData,
		"sessionid": SessionID,
		"name":      Name,
		"ownerid":   OwnerID,
	}
	response := doRequest(postData)

	var jsonResponse map[string]interface{}
	if err := json.Unmarshal([]byte(response), &jsonResponse); err != nil {
		fmt.Println("Error decoding JSON response: " + err.Error())
		time.Sleep(3 * time.Second)
		os.Exit(1)
	}

	if jsonResponse["success"].(bool) {
		return true
	} else {
		fmt.Println(jsonResponse["message"].(string))
		time.Sleep(3 * time.Second)
		os.Exit(1)
	}

	return false
}

func Ban() bool {
	CheckInit()

	postData := map[string]string{
		"type":      "ban",
		"sessionid": SessionID,
		"name":      Name,
		"ownerid":   OwnerID,
	}
	response := doRequest(postData)

	var jsonResponse map[string]interface{}
	if err := json.Unmarshal([]byte(response), &jsonResponse); err != nil {
		fmt.Println("Error decoding JSON response: " + err.Error())
		time.Sleep(3 * time.Second)
		os.Exit(1)
	}

	if jsonResponse["success"].(bool) {
		return true
	} else {
		fmt.Println(jsonResponse["message"].(string))
		time.Sleep(3 * time.Second)
		os.Exit(1)
	}

	return false
}

func Download(fileID string) []byte {
	CheckInit()

	postData := map[string]string{
		"type":      "file",
		"fileid":    fileID,
		"sessionid": SessionID,
		"name":      Name,
		"ownerid":   OwnerID,
	}

	response := doRequest(postData)

	var jsonResponse map[string]interface{}
	if err := json.Unmarshal([]byte(response), &jsonResponse); err != nil {
		fmt.Println("Error decoding JSON response: " + err.Error())
		time.Sleep(3 * time.Second)
		os.Exit(1)
	}

	if !jsonResponse["success"].(bool) {
		fmt.Println(jsonResponse["message"].(string))
		time.Sleep(3 * time.Second)
		os.Exit(1)
	}

	decodedContent, err := hex.DecodeString(jsonResponse["contents"].(string))
	if err != nil {
		fmt.Println("Error decoding file contents: " + err.Error())
		time.Sleep(3 * time.Second)
		os.Exit(1)
	}

	return decodedContent
}

func Webhook(webID, param, body, contType string) string {
	CheckInit()

	postData := map[string]string{
		"type":      "webhook",
		"webid":     webID,
		"params":    param,
		"body":      body,
		"conttype":  contType,
		"sessionid": SessionID,
		"name":      Name,
		"ownerid":   OwnerID,
	}

	response := doRequest(postData)

	var jsonResponse map[string]interface{}
	if err := json.Unmarshal([]byte(response), &jsonResponse); err != nil {
		fmt.Println("Error decoding JSON response: " + err.Error())
		time.Sleep(3 * time.Second)
		os.Exit(1)
	}

	if jsonResponse["success"].(bool) {
		return jsonResponse["message"].(string)
	} else {
		fmt.Println(jsonResponse["message"].(string))
		time.Sleep(3 * time.Second)
		os.Exit(1)
	}

	return ""
}

func CheckBlack() bool {
	CheckInit()
	hwid := GetHWID()

	postData := map[string]string{
		"type":      "checkblacklist",
		"hwid":      hwid,
		"sessionid": SessionID,
		"name":      Name,
		"ownerid":   OwnerID,
	}
	response := doRequest(postData)

	var jsonResponse map[string]interface{}
	if err := json.Unmarshal([]byte(response), &jsonResponse); err != nil {
		fmt.Println("Error decoding JSON response: " + err.Error())
		return false
	}

	return jsonResponse["success"].(bool)
}

func Log(message string) {
	CheckInit()

	postData := map[string]string{
		"type":      "log",
		"pcuser":    os.Getenv("username"),
		"message":   message,
		"sessionid": SessionID,
		"name":      Name,
		"ownerid":   OwnerID,
	}

	doRequest(postData)
}

func FetchOnline() []string {
	CheckInit()

	postData := map[string]string{
		"type":      "fetchOnline",
		"sessionid": SessionID,
		"name":      Name,
		"ownerid":   OwnerID,
	}

	response := doRequest(postData)

	var jsonResponse map[string]interface{}
	if err := json.Unmarshal([]byte(response), &jsonResponse); err != nil {
		fmt.Println("Error decoding JSON response: " + err.Error())
		return nil
	}

	if jsonResponse["success"].(bool) {
		users, ok := jsonResponse["users"].([]string)
		if ok {
			return users
		}
	}

	return nil
}

func FetchStats() {
	CheckInit()

	postData := map[string]string{
		"type":      "fetchStats",
		"sessionid": SessionID,
		"name":      Name,
		"ownerid":   OwnerID,
	}

	response := doRequest(postData)

	var jsonResponse map[string]interface{}
	if err := json.Unmarshal([]byte(response), &jsonResponse); err != nil {
		fmt.Println("Error decoding JSON response: " + err.Error())
		return
	}

	if jsonResponse["success"].(bool) {
        LoadAppData(jsonResponse["appinfo"])
	}
}

func Check() bool {
	CheckInit()

	postData := map[string]string{
		"type":      "check",
		"sessionid": SessionID,
		"name":      Name,
		"ownerid":   OwnerID,
	}
	response := doRequest(postData)

	var jsonResponse map[string]interface{}
	if err := json.Unmarshal([]byte(response), &jsonResponse); err != nil {
		fmt.Println("Error decoding JSON response: " + err.Error())
		time.Sleep(3 * time.Second)
		os.Exit(1)
	}

	return jsonResponse["success"].(bool)
}

func ChatGet(channel string) []string {
	CheckInit()

	postData := map[string]string{
		"type":      "chatget",
		"channel":   channel,
		"sessionid": SessionID,
		"name":      Name,
		"ownerid":   OwnerID,
	}

	response := doRequest(postData)

	var jsonResponse map[string]interface{}
	if err := json.Unmarshal([]byte(response), &jsonResponse); err != nil {
		fmt.Println("Error decoding JSON response: " + err.Error())
		return nil
	}

	if jsonResponse["success"].(bool) {
		messages, ok := jsonResponse["messages"].([]string)
		if ok {
			return messages
		}
	}

	return nil
}

func ChatSend(message, channel string) bool {
	CheckInit()

	postData := map[string]string{
		"type":      "chatsend",
		"message":   message,
		"channel":   channel,
		"sessionid": SessionID,
		"name":      Name,
		"ownerid":   OwnerID,
	}

	response := doRequest(postData)

	var jsonResponse map[string]interface{}
	if err := json.Unmarshal([]byte(response), &jsonResponse); err != nil {
		fmt.Println("Error decoding JSON response: " + err.Error())
		return false
	}

	return jsonResponse["success"].(bool)
}

func ChangeUsername(username string) {
	CheckInit()

	postData := map[string]string{
		"type":       "changeUsername",
		"newUsername": username,
		"sessionid":  SessionID,
		"name":       Name,
		"ownerid":    OwnerID,
	}

	response := doRequest(postData)

	var jsonResponse map[string]interface{}
	if err := json.Unmarshal([]byte(response), &jsonResponse); err != nil {
		fmt.Println("Error decoding JSON response: " + err.Error())
		time.Sleep(3 * time.Second)
		os.Exit(1)
	}

	if jsonResponse["success"].(bool) {
		fmt.Println("Successfully changed username")
	} else {
		fmt.Println(jsonResponse["message"].(string))
		time.Sleep(3 * time.Second)
		os.Exit(1)
	}
}

func Logout() {
	CheckInit()

	postData := map[string]string{
		"type":      "logout",
		"sessionid": SessionID,
		"name":      Name,
		"ownerid":   OwnerID,
	}

	response := doRequest(postData)

	var jsonResponse map[string]interface{}
	if err := json.Unmarshal([]byte(response), &jsonResponse); err != nil {
		fmt.Println("Error decoding JSON response: " + err.Error())
		time.Sleep(3 * time.Second)
		os.Exit(1)
	}

	if jsonResponse["success"].(bool) {
		fmt.Println("Successfully logged out")
	} else {
		fmt.Println(jsonResponse["message"].(string))
		time.Sleep(3 * time.Second)
		os.Exit(1)
	}
}

func CheckInit() {
	if SessionID == "lol" {
		fmt.Println("Please initialize the application before using any of its functions.")
		time.Sleep(3 * time.Second)
		os.Exit(1)
	}
}

func IsEmpty() {
	if Name == "" || OwnerID == "" || Secret == "" || Version == "" || len(OwnerID) != 10 || len(Secret) != 64 {
		fmt.Println("Application not setup properlly.")
		time.Sleep(3 * time.Second)
		os.Exit(1)
	}
}

func doRequest(postData map[string]string) string {
    requestBody := url.Values{}
    for key, value := range postData {
        requestBody.Set(key, value)
    }

    req, err := http.NewRequest("POST", APIUrl, strings.NewReader(requestBody.Encode()))
    if err != nil {
        fmt.Println("Error creating request:", err)
        return ""
    }
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

    client := http.Client{Timeout: 10 * time.Second}
    response, err := client.Do(req)
    if err != nil {
        fmt.Println("Error sending request:", err)
        return ""
    }
    defer response.Body.Close()

    responseBody, err := io.ReadAll(response.Body)
    if err != nil {
        fmt.Println("Error reading response:", err)
        return ""
    }

    key := EncKey
    if postData["type"] == "init" {
        key = Secret
    }

    clientComputed := hmac.New(sha256.New, []byte(key))
    clientComputed.Write(responseBody)
    clientComputedStr := hex.EncodeToString(clientComputed.Sum(nil))

    signature := response.Header.Get("signature")

    if clientComputedStr != signature {
        fmt.Println("Signature checksum failed. Request was tampered with or session ended most likely.")
        fmt.Println("Response:", string(responseBody))
        time.Sleep(3 * time.Second)
        os.Exit(1)
    }

    exeName := filepath.Base(os.Args[0])
    debugPath := filepath.Join("C:\\ProgramData\\KeyAuth\\Debug", exeName)

    if _, err := os.Stat(debugPath); os.IsNotExist(err) {
        if err := os.MkdirAll(debugPath, 0755); err != nil {
            fmt.Println("Error creating debug directory:", err)
        }
    }

    if len(string(responseBody)) <= 200 {
        tampered := clientComputedStr != signature
        executionTime := time.Now().Format("03:04:05 PM | 01/02/2006")
        
        redactedResponse := redactFields(responseBody)
        
        debugLog := fmt.Sprintf("\n%s | %s \nResponse: %s\nWas response tampered with? %v\n", executionTime, postData["type"], redactedResponse, tampered)
        
        if err := writeDebugLogToFile(filepath.Join(debugPath, "log.txt"), debugLog); err != nil {
            fmt.Println("Error writing debug log to file:", err)
        }
    }

    return string(responseBody)
}

func GetHWID() string {
    switch runtime.GOOS {
    case "linux":
        out, err := exec.Command("cat", "/etc/machine-id").Output()
        if err != nil {
			fmt.Println("Error reading /etc/machine-id: " + err.Error())
            return ""
        }
        hwid := string(out)
        return hwid

    case "windows":
		const xx = "cmd.exe"

		var stdout bytes.Buffer
		cmd := exec.Command(xx, "/c", "wmic useraccount where name='%username%' get sid")
		cmd.Stdout = &stdout
		err := cmd.Run()
		if err != nil {
			return ""
		}
	
		return strings.TrimSpace(strings.TrimPrefix(stdout.String(), "SID"))

    case "darwin":
        out, err := exec.Command("ioreg", "-l", "|", "grep", "IOPlatformSerialNumber").Output()
        if err != nil {
			fmt.Println("Error reading IOPlatformSerialNumber: " + err.Error())
            return ""
        }
        serial := strings.Split(string(out), "=")[1]
        hwid := strings.TrimSpace(strings.ReplaceAll(serial, " ", ""))
        return hwid

    default:
		fmt.Println("Unfortunatly you are on an unsupported OS.")
        return ""
    }
}

func checkSum(filename string) string {
    file, err := os.Open(filename)
    if err != nil { return "" }
    defer file.Close()

    hash := md5.New()
    if _, err := io.Copy(hash, file); err != nil {
        panic(err)
    }

    hashInBytes := hash.Sum(nil)
    return hex.EncodeToString(hashInBytes)
}

func LoadAppData(data interface{}) string {
    appInfo, ok := data.(map[string]interface{})
    if !ok {
        return "Error: AppInfo data is not in expected format"
    }
    NumUsers = appInfo["numUsers"].(string)
    NumKeys = appInfo["numKeys"].(string)
    CustomerPanelURL = appInfo["customerPanelLink"].(string)
    NumOnlineUsers = appInfo["numOnlineUsers"].(string)

    return "";
}

func LoadUserData(data interface{}) string {
    userInfo, ok := data.(map[string]interface{})
    if !ok {
        return "Error: UserInfo data is not in expected format"
    }

    Username = userInfo["username"].(string)
    IP = userInfo["ip"].(string)
    
    if hwidFloat, ok := userInfo["hwid"].(float64); ok {
        HWID = fmt.Sprintf("%f", hwidFloat)
    } else {
        HWID = userInfo["hwid"].(string)
    }
    if HWID == "" {
        HWID = "N/A"
    }

    subscriptions, ok := userInfo["subscriptions"].([]interface{})
    if ok && len(subscriptions) > 0 {
        subscriptionData, ok := subscriptions[0].(map[string]interface{})
        if ok {
            Expires = subscriptionData["expiry"].(string)
            Subscription = subscriptionData["subscription"].(string)
        }
    }

    CreatedDate = userInfo["createdate"].(string)
    LastLogin = userInfo["lastlogin"].(string)
    subscriptionsJSON, err := json.Marshal(subscriptions)
    if err != nil { 
        return "Error converting subscriptions to JSON: " + err.Error() 
    }
    Subscriptions = string(subscriptionsJSON)
    return ""
}

func openUrl(url string) error {
    var cmd string
    var args []string

    switch runtime.GOOS {
    case "windows":
        cmd = "cmd"
        args = []string{"/c", "start"}
    case "darwin":
        cmd = "open"
    default:
        cmd = "xdg-open"
    }
    args = append(args, url)
    return exec.Command(cmd, args...).Start()
}

func writeDebugLogToFile(filePath, debugLog string) error {
    file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
    if err != nil {
        return err
    }
    defer file.Close()

    _, err = file.WriteString(debugLog)
    if err != nil {
        return err
    }

    return nil
}

func tokenHash(tokenPath string) string {
	data, err := ioutil.ReadFile(tokenPath)
	if err != nil {
		panic(err)
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func redactFields(responseBody []byte) string {
    var responseMap map[string]interface{}
    if err := json.Unmarshal(responseBody, &responseMap); err != nil {
        fmt.Println("Error unmarshalling response:", err)
        return string(responseBody)
    }

    sensitiveFields := []string{"sessionid", "ownerid", "app", "secret", "version", "fileid", "webhooks"}

    for _, field := range sensitiveFields {
        if _, exists := responseMap[field]; exists {
            responseMap[field] = "REDACTED"
        }
    }

    redactedResponse, err := json.Marshal(responseMap)
    if err != nil {
        fmt.Println("Error marshalling redacted response:", err)
        return string(responseBody)
    }

    return string(redactedResponse)
}