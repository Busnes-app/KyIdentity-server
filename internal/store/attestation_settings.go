package store

// AttestationSettings is the admin policy applied when grading device attestations.
type AttestationSettings struct {
	RequireLockedBootloader bool `json:"requireLockedBootloader"`
}

// AttestationSettings returns the default policy until the admin setting lands.
func (s *Store) AttestationSettings() (AttestationSettings, error) {
	return AttestationSettings{}, nil
}
