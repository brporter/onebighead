package utility

import "io/ioutil"

// IOHelper defines the interface of types capable of performing I/O operations on files
type IOHelper interface {
	Get(filename string) ([]byte, error)
}

type systemIOHelper struct {
}

// IOHelperGeneratorFunc is a function capable of returning an implementation of the IOHelper interface
type IOHelperGeneratorFunc func() IOHelper

// IOHelperGenerator is a function that is capable of generating a new IOHelper
var IOHelperGenerator IOHelperGeneratorFunc = func() IOHelper {
	return &systemIOHelper{}
}

// NewIOHelper creates a new IOHelper
func NewIOHelper() IOHelper {
	return IOHelperGenerator()
}

// FileGet retrieves the contents of the specified file
func FileGet(filename string) ([]byte, error) {
	helper := NewIOHelper()
	return helper.Get(filename)
}

// Get retrieves the contents of the specified file
func (*systemIOHelper) Get(filename string) ([]byte, error) {
	contents, err := ioutil.ReadFile(filename)

	if err != nil {
		return nil, err
	}

	return contents, nil
}
