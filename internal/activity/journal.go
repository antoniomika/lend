package activity

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const maxJournal = 8 * 1024 * 1024

func ReadHistory(path string) ([]Entry, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != uint32(os.Getuid()) || info.Mode().Perm() != 0600 || info.Size() > maxJournal {
		return nil, errors.New("history must be a private regular file owned by you, no larger than 8 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxJournal+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxJournal {
		return nil, errors.New("history exceeds 8 MiB")
	}
	lines := bytes.Split(data, []byte{'\n'})
	records := []Entry{}
	// A writer may still be appending the final record.
	for _, line := range lines[:len(lines)-1] {
		var entry Entry
		if json.Unmarshal(line, &entry) != nil {
			return nil, errors.New("history contains an invalid record")
		}
		entry.Info = nil
		records = append(records, entry)
		if len(records) > 256 {
			records = records[1:]
		}
	}
	return records, nil
}

type Journal struct {
	file     *os.File
	lock     *os.File
	path     string
	Previous []Entry
}

func OpenJournal(path string) (*Journal, error) {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	info, err := os.Stat(directory)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) || info.Mode().Perm() != 0700 {
		return nil, errors.New("history directory must be owned by you with mode 0700")
	}
	lock, err := openJournalFile(path + ".lock")
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		lock.Close()
		return nil, err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	file, err := openJournalFile(path)
	if err != nil {
		lock.Close()
		return nil, err
	}
	j := &Journal{file: file, lock: lock, path: path}
	scan := bufio.NewScanner(io.LimitReader(file, maxJournal+1))
	scan.Buffer(make([]byte, 4096), 64*1024)
	for scan.Scan() {
		var entry Entry
		if json.Unmarshal(scan.Bytes(), &entry) != nil {
			file.Close()
			lock.Close()
			return nil, errors.New("history contains an invalid record")
		}
		entry.Info = nil
		j.Previous = append(j.Previous, entry)
		if len(j.Previous) > 256 {
			j.Previous = j.Previous[1:]
		}
	}
	if err := scan.Err(); err != nil {
		file.Close()
		lock.Close()
		return nil, err
	}
	return j, nil
}

func openJournalFile(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != uint32(os.Getuid()) || info.Mode().Perm() != 0600 || info.Size() > maxJournal {
		file.Close()
		return nil, errors.New("history must be a private regular file owned by you, no larger than 8 MiB")
	}
	return file, nil
}

func (j *Journal) Append(entry Entry) error {
	if err := syscall.Flock(int(j.lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(j.lock.Fd()), syscall.LOCK_UN)
	// Another session can rotate the shared file between writes.
	j.file.Close()
	file, err := openJournalFile(j.path)
	if err != nil {
		return err
	}
	j.file = file
	entry.Info = nil
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	info, err := j.file.Stat()
	if err != nil {
		return err
	}
	if info.Size()+int64(len(data)+1) > maxJournal {
		if err := j.file.Close(); err != nil {
			return err
		}
		if err := os.Rename(j.path, j.path+".1"); err != nil {
			return err
		}
		j.file, err = openJournalFile(j.path)
		if err != nil {
			return err
		}
	}
	_, err = j.file.Write(append(data, '\n'))
	return err
}

func (j *Journal) Close() error {
	if j == nil {
		return nil
	}
	if j.lock != nil {
		j.lock.Close()
	}
	if j.file != nil {
		return j.file.Close()
	}
	return nil
}
