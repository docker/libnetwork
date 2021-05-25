/*
Package ipset implements netfilter's ipset
This is currently work in program and feedback is welcome
*/
package ipset

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// ipset commands
type option string
type timeout uint

//

var (
	ipsetPath string

	//_TypeNameMethods: Possible Typename Methods defined in ipset  man page
	//true if enabled, false otherwise
	_TypeNameMethods = map[string]bool{
		"bitmap": true,
		"hash":   true,
		"list":   true,
	}

	//Possible values for Typename datatypes
	_TypeNameDataType = map[string]bool{
		"ip":    true,
		"net":   true,
		"mac":   true,
		"port":  true,
		"iface": true,
	}
	//_CreateOptionsBitmap Possible create options, see ipset man page
	_CreateOptionsBitmap = map[string]bool{
		"timeout": true, //int
		//add netmask on bitmap:ip structure definition
		"range":    true, //fromip-toip|ip/cidr , mandatory
		"counters": true, //flag
		"comment":  true, //flag

	}

	_CreateOptionsHash = map[string]bool{
		"timeout": true, //int
		//add "netmask" : true on hash:ip//cidr
		"counters": true, //flag
		"comment":  true, //flag
		"familly":  true, // inet
		"hashsize": true, //int, power of 2, default 1024, kernel rounds up non power of two.
		"maxelem":  true, //int
	}

	_CreateOptionsList = map[string]bool{
		"size":     true, //int
		"timeout":  true, //int
		"counters": true, //flag
		"comment":  true, //flag
	}

	_CreateOptionsExceptionsValues = map[string]bool{
		"netmask": true, //cidr
	}
	_CreateOptionsExceptions = map[string]map[string]bool{
		"bitmap:ip_netmask": _CreateOptionsExceptionsValues,
		"hash:ip_netmask":   _CreateOptionsExceptionsValues,
	}

	_CreateOptions = map[string]map[string]bool{
		"bitmap:ip":           _CreateOptionsBitmap,
		"bitmap:ip,mac":       _CreateOptionsBitmap,
		"bitmap:ip,port":      _CreateOptionsBitmap,
		"hash:ip":             _CreateOptionsHash,
		"hash:ip,net":         _CreateOptionsHash,
		"hash:net":            _CreateOptionsHash,
		"hash:net,net":        _CreateOptionsHash,
		"hash:ip,port":        _CreateOptionsHash,
		"hash:net,port":       _CreateOptionsHash,
		"hash:ip,port,ip":     _CreateOptionsHash,
		"hash:ip,port,net":    _CreateOptionsHash,
		"hash:net,port,net":   _CreateOptionsHash,
		"hash:net,port,iface": _CreateOptionsHash,
		"list:set":            _CreateOptionsList,
	}
	//ERRORS
	errIpsetNotFound = errors.New("ipset Not found")
	//can only be bitmap, hash, list
	errInvalidTNMethod      = errors.New("Invalid TYPENAME method")
	errInvalidTNDataType    = errors.New("Typename datatype incorrect")
	errInvalidCreateOptions = errors.New("Invalid create options supplied, make sure it is valid for your TYPENAME")
)

func init() {
	err := initCheck()
	if err != nil {
		fmt.Println("Error:", err)

	}
}
func initCheck() error {
	if ipsetPath == "" {
		path, err := exec.LookPath("ipset")
		if err != nil {
			return errIpsetNotFound
		}

		ipsetPath = path
	}
	return nil
}

// VERIFIES TYPENAME is according to ipset's requirement
func validTypeName(tnMethod string, tnDataType []string) (err error) {
	//Do we support that TYPENAME METHOD
	// bitmap, hash, list
	if !_TypeNameMethods[tnMethod] {
		return errInvalidTNMethod
	}
	// we can't allow more data types than supported  (ip, net, mac, port and iface )
	if len(tnDataType) > len(_TypeNameDataType) {
		return errInvalidTNDataType
	}

	for _, tnDT := range tnDataType {

		if !(_TypeNameDataType[tnDT]) {
			return errInvalidTNDataType
		}
	}
	return nil
}

func trimEntireSlice(aSlice []string) []string {

	for index, element := range aSlice {
		aSlice[index] = strings.Trim(element, " ")
	}
	return aSlice
}

func generateTypeName(tnMethod string, tnDataType []string) string {
	tnDataType = trimEntireSlice(tnDataType)
	return strings.Trim(tnMethod, " ") + ":" + strings.Join(tnDataType[:], ",")
}

func validCreateOptions(tnMethod string, tnDataType []string, createOptions map[string]string) (err error) {
	//validate createOptions
	//we need to check the value of each create-option's value
	//ignore this for now
	vcoTypeName := generateTypeName(tnMethod, tnDataType)

	for key, value := range createOptions {
		vcoException := vcoTypeName + "_" + key
		if !(_CreateOptions[vcoTypeName][key] || _CreateOptionsExceptions[vcoException][key]) {
			fmt.Println("value:", value) //replace with value checker
			return errInvalidCreateOptions
		}
	}
	//no errors, valid create options
	return nil
}

func generateCreateOption(createOptions map[string]string) []string {
	var gcoCreateOptions []string
	var buf string
	for key, value := range createOptions {
		trimmedValue := strings.Trim(value, " ")
		if trimmedValue == "" {
			buf = strings.Trim(key, " ")
			gcoCreateOptions = append(gcoCreateOptions, buf)
		} else {
			buf = strings.Trim(key, " ")
			gcoCreateOptions = append(gcoCreateOptions, strings.Trim(key, " ")+" "+trimmedValue)
		}

	}
	return gcoCreateOptions
}

// Create does exactly what the ipset man page says. See example below:
//   var typenet = [] string {"net":"net"}
//   var myoptions = map[string] string { "timeout" : "30", "counters": "", }
//   Create("myset", "hash", typenet, myoptions )
func Create(setname string, tnMethod string, tnDataType []string, createOptions map[string]string) (output string, err error) {
	//Output of our ipset create
	var out bytes.Buffer
	var arguments []string
	//verify if TYPENAME is valid, see ipset manpage
	//work towards deprecating this check
	err = validTypeName(tnMethod, tnDataType)
	if err != nil {
		return "", err
	}

	// verify if CREATE-OPTIONS is valid, see ipset manpage
	err = validCreateOptions(tnMethod, tnDataType, createOptions)
	if err != nil {
		return "", err
	}
	//reset error, as we are reusing it to return run failures
	err = nil
	//modify generateTypeName and generateCreateOptions to return a slice of string
	// use slice append(s1,s2) to merge to slices.
	//exec takes args as a slice also
	typeName := generateTypeName(tnMethod, tnDataType)
	generatedCreateOptions := generateCreateOption(createOptions)
	arguments = []string{setname, typeName}
	arguments = append(arguments, generatedCreateOptions...)
	fmt.Println(arguments)
	cmd := exec.Command(ipsetPath, arguments...)
	cmd.Stdout = &out
	err = cmd.Run()

	return out.String(), err

}

//should be called only by Save(), List(), Destroy()
func dlsAction(options []string, setAction string, setname string) (string, error) {
	var cmd *exec.Cmd
	var out bytes.Buffer
	if len(options) == 0 {
		cmd = exec.Command(ipsetPath, setAction, setname)
	} else {
		return "", nil //TODO: just merge options and setname in one slice and pass to cmd
	}

	cmd.Stdout = &out
	err := cmd.Run()
	return out.String(), err
}

//Save supports only defaults for now, see ipset man page for details
func Save(setname string, options []string) (string, error) {
	if len(options) == 0 {
		return dlsAction(options, "save", setname)
	}
	return "", nil
}

//List supports only defaults for now, see ipset man page for details
func List(setname string, options []string) (string, error) {

	if len(options) == 0 {
		return dlsAction(options, "list", setname)
	}
	return "", nil
}

//Destroy supports only defaults for now, see ipset man page for details
func Destroy(setname string, options []string) (string, error) {

	if len(options) == 0 {
		return dlsAction(options, "destroy", setname)
	}
	return "", nil
}

//Flush supports only defaults for now, see ipset man page for details
func Flush(setname string, options []string) (string, error) {

	if len(options) == 0 {
		return dlsAction(options, "flush", setname)
	}
	return "", nil
}
