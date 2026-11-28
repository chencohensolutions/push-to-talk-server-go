package blobs

import "golang.org/x/sys/windows"

// freeBytes is the space left for this user on the disk that holds dir, or -1 when it can't be read.
func freeBytes(dir string) int64 {
	path, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return -1
	}
	var free, total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(path, &free, &total, &totalFree); err != nil {
		return -1
	}
	return int64(free)
}
