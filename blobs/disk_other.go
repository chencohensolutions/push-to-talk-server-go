//go:build !windows

package blobs

import "golang.org/x/sys/unix"

// freeBytes is the space left for this user on the disk that holds dir, or -1 when it can't be read.
func freeBytes(dir string) int64 {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return -1
	}
	return int64(st.Bavail) * int64(st.Bsize)
}
