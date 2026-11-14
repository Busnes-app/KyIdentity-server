package store

import "strings"

// SuitePerson is one entry of the suite people picker.
type SuitePerson struct {
	ID, Name, Email string
}

// SuitePeople lists active everyday users who may open clientID: those whose display name
// has a word starting with q or whose username or email starts with q, or, when emails is
// set, those with exactly those addresses. Administrator accounts are never listed. At most
// limit rows, ordered by name.
func (s *Store) SuitePeople(clientID, q string, emails []string, limit int) ([]SuitePerson, error) {
	match, args := `u.email IN (?`+strings.Repeat(",?", max(len(emails)-1, 0))+`)`, []any{clientID}
	if emails == nil {
		p := likePrefix(q)
		match = `(u.display_name LIKE ? ESCAPE '\' OR u.display_name LIKE ? ESCAPE '\' OR u.username LIKE ? ESCAPE '\' OR u.email LIKE ? ESCAPE '\')`
		args = append(args, p, "% "+p, p, p)
	} else {
		for _, e := range emails {
			args = append(args, e)
		}
	}
	rows, err := s.db.Query(`SELECT u.id, CASE WHEN u.display_name<>'' THEN u.display_name ELSE u.username END, u.email FROM users u
 WHERE u.role='user' AND NOT u.pending AND u.email<>''
 AND EXISTS(SELECT 1 FROM effective_app_access e JOIN app_registry a ON a.id=e.app_id JOIN oauth_clients c ON c.id=a.client_id WHERE e.user_id=u.id AND c.id=? AND c.enabled)
 AND `+match+` ORDER BY lower(u.display_name), u.id LIMIT ?`, append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SuitePerson{}
	for rows.Next() {
		var p SuitePerson
		if err := rows.Scan(&p.ID, &p.Name, &p.Email); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
