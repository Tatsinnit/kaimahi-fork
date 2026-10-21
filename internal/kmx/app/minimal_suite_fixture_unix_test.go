//go:build !windows

package app

// minimalSuiteFixture is the checked-in suite directory itself.
func minimalSuiteFixture(source string) string { return source }
