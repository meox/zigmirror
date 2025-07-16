package registry

import "sync"

type SafeDownload struct {
	m sync.Mutex
	v map[string]bool
}

func Init() *SafeDownload {
	return &SafeDownload{
		v: make(map[string]bool),
	}
}

func (s *SafeDownload) StartDownload(fileName string) bool {
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

func (s *SafeDownload) DownloadComplete(fileName string) {
	s.m.Lock()
	defer s.m.Unlock()

	delete(s.v, fileName)
}
