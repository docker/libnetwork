// +build debug_log
package libnetwork

import "github.com/sirupsen/logrus"

func debugf(format string, args ...interface{}) {
	logrus.Debugf(format, args...)
}
