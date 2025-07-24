package mlock

import "sync"

type MLock struct {
	m sync.Mutex
	v map[string]bool
}

func Init() *MLock {
	return &MLock{
		v: make(map[string]bool),
	}
}

func (s *MLock) StartDownload(fileName string) bool {
	s.m.Lock()
	defer s.m.Unlock()

	d, ok := s.v[fileName]
	if ok && d {
		// already downloading
		return false
	}

	s.v[fileName] = true
	return true
}

func (s *MLock) DownloadComplete(fileName string) {
	s.m.Lock()
	defer s.m.Unlock()

	delete(s.v, fileName)
}
