package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"mime/multipart"
	"net/http"
	"path"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

// Attachments of forum messages. Users: a picture up to 1 MB and a file up to 10 MB per message, each kind only if the
// administrator allows it, and no more than forumUserQuota stored per account. The administrator has no limits (apart from a
// technical ceiling) and may always attach. Files are served only to logged-in users: pictures inline (their type is checked
// by the content), everything else as a download with a neutral type, so an uploaded page can never run on the site.

const (
	forumImageMax   = 1 << 20
	forumFileMax    = 10 << 20
	forumMaxRequest = forumImageMax + forumFileMax + (256 << 10)
	forumUserQuota  = 100 << 20
	forumStaffMax   = 200 << 20
)

type Attachment struct {
	Name, Mime, Kind string
	Data             []byte
}

type ForumFile struct {
	ID   int64  `json:"id"`
	Kind string `json:"kind"`
	Name string `json:"name"`
	Mime string `json:"mime"`
	Size int64  `json:"size"`
}

var imageExt = map[string]string{"image/png": ".png", "image/jpeg": ".jpg", "image/gif": ".gif", "image/webp": ".webp"}

// sniffImage returns the type of a picture by its content ("" = not a picture we show). SVG is deliberately not accepted.
func sniffImage(data []byte) string {
	t := http.DetectContentType(data)
	if _, ok := imageExt[t]; !ok {
		return ""
	}
	if t != "image/webp" { // the others must really decode
		if _, _, err := image.DecodeConfig(bytes.NewReader(data)); err != nil {
			return ""
		}
	}
	return t
}

func cleanFileName(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	name = path.Base(name)
	name = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 || r == '"' || r == '<' || r == '>' || r == ';' {
			return -1
		}
		return r
	}, name)
	name = strings.TrimSpace(strings.Trim(name, "."))
	if !utf8.ValidString(name) || name == "" || name == "/" {
		name = "file"
	}
	if r := []rune(name); len(r) > 100 {
		name = string(r[:100])
	}
	return name
}

// checkAttachment validates one attachment. want is "image", "file" or "" (staff: decide by the content).
func checkAttachment(want, name string, data []byte, staff bool) (Attachment, error) {
	if len(data) == 0 {
		return Attachment{}, errors.New("пустой файл")
	}
	name = cleanFileName(name)
	img := sniffImage(data)
	switch {
	case want == "image" || (want == "" && img != ""):
		if img == "" {
			return Attachment{}, errors.New("это не картинка (поддерживаются PNG, JPEG, GIF и WebP)")
		}
		if !staff && len(data) > forumImageMax {
			return Attachment{}, fmt.Errorf("картинка больше %d МБ", forumImageMax>>20)
		}
		if ext := imageExt[img]; !strings.EqualFold(path.Ext(name), ext) && !(img == "image/jpeg" && strings.EqualFold(path.Ext(name), ".jpeg")) {
			name = strings.TrimSuffix(name, path.Ext(name)) + ext
		}
		return Attachment{Name: name, Mime: img, Kind: "image", Data: data}, nil
	default:
		if !staff && len(data) > forumFileMax {
			return Attachment{}, fmt.Errorf("файл больше %d МБ", forumFileMax>>20)
		}
		return Attachment{Name: name, Mime: "application/octet-stream", Kind: "file", Data: data}, nil
	}
}

// ---- store ----

func (s *Store) AccountFileBytes(ctx context.Context, accID int64) int64 {
	var n int64
	_ = s.pool.QueryRow(ctx, `SELECT COALESCE(SUM(size),0) FROM forum_files WHERE account_id=$1`, accID).Scan(&n)
	return n
}

func addFiles(ctx context.Context, tx pgx.Tx, postID int64, accID *int64, atts []Attachment) error {
	for _, a := range atts {
		if _, err := tx.Exec(ctx, `INSERT INTO forum_files(post_id,account_id,kind,name,mime,size,data) VALUES($1,$2,$3,$4,$5,$6,$7)`,
			postID, accID, a.Kind, a.Name, a.Mime, int64(len(a.Data)), a.Data); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) filesOfPosts(ctx context.Context, ids []int64) (map[int64][]ForumFile, error) {
	out := map[int64][]ForumFile{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT id, post_id, kind, name, mime, size FROM forum_files WHERE post_id = ANY($1) ORDER BY id`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var f ForumFile
		var pid int64
		if err := rows.Scan(&f.ID, &pid, &f.Kind, &f.Name, &f.Mime, &f.Size); err != nil {
			return nil, err
		}
		out[pid] = append(out[pid], f)
	}
	return out, rows.Err()
}

// GetFile returns a file; a user does not get files of hidden topics or messages.
func (s *Store) GetFile(ctx context.Context, id int64, withHidden bool) (*ForumFile, []byte, error) {
	var f ForumFile
	var data []byte
	err := s.pool.QueryRow(ctx, `SELECT f.id, f.kind, f.name, f.mime, f.size, f.data FROM forum_files f
		JOIN forum_posts p ON p.id=f.post_id JOIN forum_topics t ON t.id=p.topic_id
		WHERE f.id=$1 AND ((NOT p.hidden AND NOT t.hidden) OR $2)`, id, withHidden).Scan(&f.ID, &f.Kind, &f.Name, &f.Mime, &f.Size, &data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	return &f, data, err
}

func (s *Store) DeleteFile(ctx context.Context, id int64) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM forum_files WHERE id=$1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ---- reading the form ----

// formAttachments takes the attachments out of a parsed multipart form, checking the permissions and limits of an ordinary user.
func (s *Site) formAttachments(r *http.Request, acc *Account) ([]Attachment, error) {
	if r.MultipartForm == nil {
		return nil, nil
	}
	sc := s.cfg.getSite()
	var out []Attachment
	var total int64
	for _, field := range []string{"image", "file"} {
		for _, fh := range r.MultipartForm.File[field] {
			if len(out) >= 2 {
				return nil, errors.New("не больше одной картинки и одного файла в сообщении")
			}
			if field == "image" && !sc.ForumImages {
				return nil, errors.New("прикладывать картинки сейчас нельзя")
			}
			if field == "file" && !sc.ForumFiles {
				return nil, errors.New("прикладывать файлы сейчас нельзя")
			}
			max := int64(forumFileMax)
			if field == "image" {
				max = forumImageMax
			}
			if fh.Size > max {
				return nil, fmt.Errorf("%s больше %d МБ", map[string]string{"image": "картинка", "file": "файл"}[field], max>>20)
			}
			data, err := readPart(fh, max)
			if err != nil {
				return nil, err
			}
			a, err := checkAttachment(field, fh.Filename, data, false)
			if err != nil {
				return nil, err
			}
			total += int64(len(data))
			out = append(out, a)
		}
	}
	if total > 0 && s.st.AccountFileBytes(r.Context(), acc.ID)+total > forumUserQuota {
		return nil, fmt.Errorf("исчерпан лимит вложений на аккаунт (%d МБ)", forumUserQuota>>20)
	}
	return out, nil
}

func readPart(fh *multipart.FileHeader, max int64) ([]byte, error) {
	f, err := fh.Open()
	if err != nil {
		return nil, errors.New("не удалось прочитать файл")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, errors.New("не удалось прочитать файл")
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("файл больше %d МБ", max>>20)
	}
	return data, nil
}

// serveFile gives a stored file to a logged-in user.
func (s *Site) forumFile(w http.ResponseWriter, r *http.Request) {
	acc, _ := s.authed(w, r)
	if acc == nil {
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	f, data, err := s.st.GetFile(r.Context(), id, false)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	writeStoredFile(w, f, data)
}

func writeStoredFile(w http.ResponseWriter, f *ForumFile, data []byte) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	h.Set("Cache-Control", "private, max-age=3600")
	if f.Kind == "image" {
		h.Set("Content-Type", f.Mime)
		h.Set("Content-Disposition", `inline; filename="`+asciiName(f.Name)+`"`)
	} else {
		h.Set("Content-Type", "application/octet-stream")
		h.Set("Content-Disposition", `attachment; filename="`+asciiName(f.Name)+`"; filename*=UTF-8''`+pctName(f.Name))
	}
	h.Set("Content-Length", strconv.Itoa(len(data)))
	w.Write(data)
}

func asciiName(n string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 || r > 126 || r == '"' || r == '\\' {
			return '_'
		}
		return r
	}, n)
}

func pctName(n string) string {
	var b strings.Builder
	for _, c := range []byte(n) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// SizeText is the size of a file for the page.
func (f ForumFile) SizeText() string { return fmtBytesRu(f.Size) }
