package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

func (a *API) registerForum(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/forum/topics", a.auth(a.forumTopics))
	mux.HandleFunc("GET /api/forum/topics/{id}", a.auth(a.forumTopicGet))
	mux.HandleFunc("POST /api/forum/topics/{id}/reply", a.auth(a.forumStaffReply))
	mux.HandleFunc("POST /api/forum/topics/{id}/{op}", a.auth(a.forumTopicOp))
	mux.HandleFunc("DELETE /api/forum/topics/{id}", a.auth(a.forumTopicDelete))
	mux.HandleFunc("POST /api/forum/posts/{id}/{op}", a.auth(a.forumPostOp))
	mux.HandleFunc("GET /api/forum/files/{id}", a.auth(a.forumFileGet))
	mux.HandleFunc("DELETE /api/forum/files/{id}", a.auth(a.forumFileDelete))
}

func (a *API) forumFail(w http.ResponseWriter, err error) {
	code := 400
	if errors.Is(err, ErrNotFound) {
		code = 404
	}
	apiErr(w, code, err)
}

func (a *API) forumTopics(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("p"))
	if page < 1 {
		page = 1
	}
	ts, err := a.store.ListTopics(r.Context(), true, 100, (page-1)*100)
	if err != nil {
		apiErr(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"topics": ts, "waiting": a.store.OpenTopics(r.Context())})
}

func (a *API) forumTopicGet(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	t, posts, err := a.store.GetTopic(r.Context(), id, true)
	if err != nil {
		a.forumFail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"topic": t, "posts": posts})
}

// forumStaffReply is the answer of the administrator: JSON {body}, or a multipart form with "body" and any number of "file" parts.
// The administrator has no size limits and no permissions to ask for (only a technical ceiling).
func (a *API) forumStaffReply(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var body string
	var atts []Attachment
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		r.Body = http.MaxBytesReader(w, r.Body, forumStaffMax)
		if err := r.ParseMultipartForm(8 << 20); err != nil {
			apiErr(w, 400, fmt.Errorf("не удалось принять форму: %v", err))
			return
		}
		defer r.MultipartForm.RemoveAll()
		body = r.FormValue("body")
		for _, fh := range r.MultipartForm.File["file"] {
			data, err := readPart(fh, forumStaffMax)
			if err != nil {
				apiErr(w, 400, err)
				return
			}
			at, err := checkAttachment("", fh.Filename, data, true)
			if err != nil {
				apiErr(w, 400, err)
				return
			}
			atts = append(atts, at)
		}
	} else {
		var in struct {
			Body string `json:"body"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&in); err != nil {
			apiErr(w, 400, fmt.Errorf("ожидается JSON {body}"))
			return
		}
		body = in.Body
	}
	if err := a.store.AddPostA(r.Context(), id, nil, true, body, atts); err != nil {
		a.forumFail(w, err)
		return
	}
	a.forumTopicGet(w, r)
}

func (a *API) forumFileGet(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	f, data, err := a.store.GetFile(r.Context(), id, true)
	if err != nil {
		a.forumFail(w, err)
		return
	}
	writeStoredFile(w, f, data)
}

func (a *API) forumFileDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := a.store.DeleteFile(r.Context(), id); err != nil {
		a.forumFail(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "готово"})
}

func (a *API) forumTopicOp(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := a.store.TopicOp(r.Context(), id, r.PathValue("op")); err != nil {
		a.forumFail(w, err)
		return
	}
	a.forumTopicGet(w, r)
}

func (a *API) forumTopicDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := a.store.DeleteTopic(r.Context(), id); err != nil {
		a.forumFail(w, err)
		return
	}
	a.forumTopics(w, r)
}

func (a *API) forumPostOp(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := a.store.PostOp(r.Context(), id, r.PathValue("op")); err != nil {
		a.forumFail(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "готово"})
}
