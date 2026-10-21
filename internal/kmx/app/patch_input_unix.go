//go:build !windows

package app

import "context"

func (a *App) orkaPatchCapture(ctx context.Context, body []byte, args ...string) ([]byte, error) {
	return a.orkaCapture(ctx, body, args...)
}
