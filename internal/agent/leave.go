package agent

import (
	"errors"
	"log"
	"net/http"
	"time"

	"hltunnel/internal/config"
	"hltunnel/internal/engine"
)

// contactEvery is how often a master's last contact is written down: often
// enough for a count in days, rarely enough not to rewrite the settings on
// every status call.
const contactEvery = 10 * time.Minute

// noteContact records that the master with key reached us (see
// config.SilentMasters).
func noteContact(st *config.State, key string) {
	m := st.MasterByKey(key)
	if m == nil || time.Since(m.LastContact) < contactEvery {
		return
	}
	config.Update(func(st *config.State) error {
		if m := st.MasterByKey(key); m != nil {
			m.LastContact = time.Now()
		}
		return nil
	})
}

// leave forgets the asking master: its tunnels, forwards and IPsec go now.
// The other masters keep theirs.
func (s *Server) leave(w http.ResponseWriter, r *http.Request) {
	key := master(r)
	var gone *config.Managed
	st, err := config.Update(func(st *config.State) error {
		if gone = st.ForgetMaster(key); gone == nil {
			return errors.New("not my master")
		}
		return nil
	})
	if err != nil {
		fail(w, http.StatusConflict, err)
		return
	}
	log.Printf("main server %s let this server go: removing its %d tunnels", gone.Master.Name, len(gone.Tunnels))
	engine.Apply(st)
	if s.Applied != nil {
		s.Applied()
	}
	writeJSON(w, http.StatusOK, LeaveResponse{Tunnels: len(gone.Tunnels)})
}

// restore lets the master's tunnels removed here by hand run again.
func (s *Server) restore(w http.ResponseWriter, r *http.Request) {
	var req RestoreRequest
	if err := readJSON(r, &req); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	key := master(r)
	st, err := config.Update(func(st *config.State) error {
		m := st.MasterByKey(key)
		if m == nil {
			return errors.New("not my master")
		}
		m.Restore(req.Names)
		return nil
	})
	if err != nil {
		fail(w, http.StatusConflict, err)
		return
	}
	engine.Apply(st)
	if s.Applied != nil {
		s.Applied()
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
