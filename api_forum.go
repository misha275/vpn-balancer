package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
)

func (a *API) registerForum(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/forum/topics", a.auth(a.forumTopics))
	mux.HandleFunc("GET /api/forum/topics/{id}", a.auth(a.forumTopicGet))
	mux.HandleFunc("POST /api/forum/topics/{id}/reply", a.auth(a.forumStaffReply))
	mux.HandleFunc("POST /api/forum/topics/{id}/{op}", a.auth(a.forumTopicOp))
	mux.HandleFunc("DELETE /api/forum/topics/{id}", a.auth(a.forumTopicDelete))
	mux.HandleFunc("POST /api/forum/posts/{id}/{op}", a.auth(a.forumPostOp))
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

func (a *API) forumStaffReply(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Body string `json:"body"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&in); err != nil {
		apiErr(w, 400, fmt.Errorf("ожидается JSON {body}"))
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := a.store.AddPost(r.Context(), id, nil, true, in.Body); err != nil {
		a.forumFail(w, err)
		return
	}
	a.forumTopicGet(w, r)
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
