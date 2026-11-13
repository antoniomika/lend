package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/picosh/pdocs"
)

func main() {
	serve := flag.String("serve", "", "serve the generated site at this address")
	flag.Parse()
	if err := generate(); err != nil {
		log.Fatal(err)
	}
	if *serve != "" {
		log.Printf("Lend docs: http://%s (rerun to rebuild after edits)", *serve)
		log.Fatal(http.ListenAndServe(*serve, http.FileServer(http.Dir("public"))))
	}
}

func generate() error {
	stage, err := os.MkdirTemp(".", ".build-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	output := filepath.Join(stage, "public")
	pager := pdocs.Pager("posts")
	page := func(title, slug string) *pdocs.Sitemap {
		return &pdocs.Sitemap{Text: title, Href: "/" + slug + ".html", Page: pager(slug + ".md")}
	}
	sitemap := &pdocs.Sitemap{Children: []*pdocs.Sitemap{
		{Text: "Home", Href: "/", Page: pager("home.md")},
		{Text: "Start here", Children: []*pdocs.Sitemap{
			page("Getting started", "getting-started"),
			page("Installation", "installation"),
			page("How it works", "how-it-works"),
		}},
		{Text: "Configure access", Children: []*pdocs.Sitemap{
			page("Command policy", "command-policy"),
			page("SSH keys", "ssh-keys"),
			page("Agent management", "agent-management"),
			page("Approval and callers", "approval"),
			page("Sessions and leases", "sessions"),
			page("Credentials and environment", "credentials"),
		}},
		{Text: "Use Lend", Children: []*pdocs.Sitemap{
			page("Running commands", "commands"),
			page("MCP", "mcp"),
			page("Activity and history", "activity"),
			page("CLI reference", "cli"),
			page("Cheatsheet", "cheatsheet"),
		}},
		{Text: "Reference", Children: []*pdocs.Sitemap{
			page("Doctor", "doctor"),
			page("Scope and trust", "security"),
			page("Development", "development"),
		}},
		page("Sitemap", "sitemap"),
	}}
	// Keep the wire protocol and release guide in their existing source files.
	for _, doc := range []struct{ slug, title, description string }{
		{"protocol", "Protocol", "The SSH agent extension, execution stream, and local control protocol."},
		{"releasing", "Releasing", "Build release archives and maintain the Homebrew tap."},
	} {
		content, err := os.ReadFile(doc.slug + ".md")
		if err != nil {
			return err
		}
		body := strings.TrimPrefix(string(content), "# "+doc.title+"\n")
		body = strings.ReplaceAll(body, "(release-notes.md)", "(https://github.com/antoniomika/lend/blob/main/docs/release-notes.md)")
		title, _ := json.Marshal(doc.title)
		description, _ := json.Marshal(doc.description)
		path := filepath.Join(stage, doc.slug+".md")
		if err := os.WriteFile(path, []byte(fmt.Sprintf("---\ntitle: %s\ndescription: %s\ntoc: true\n---\n%s", title, description, body)), 0644); err != nil {
			return err
		}
		item := &pdocs.Sitemap{Text: doc.title, Href: "/" + doc.slug + ".html", Page: path}
		reference := sitemap.Children[len(sitemap.Children)-2]
		reference.Children = append(reference.Children, item)
	}
	config := &pdocs.DocConfig{
		Logger: slog.Default(), Sitemap: sitemap, Out: output,
		Tmpl: "tmpl", PageTmpl: "post.page.tmpl",
	}
	if err := config.GenSite(); err != nil {
		return err
	}
	if err := copyTree("static", output); err != nil {
		return err
	}
	if err := copyTree("../examples", filepath.Join(output, "examples")); err != nil {
		return err
	}
	if err := os.RemoveAll("public"); err != nil {
		return err
	}
	return os.Rename(output, "public")
}

func copyTree(source, destination string) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0644)
	})
}
