package main

// backup export (#118 D9): the owner's own copy of a sandbox's off-host
// backup, for the restore without the platform (docs/offline-restore.md).
// The entry point's "backup export NAME --json" gives short-lived URLs for
// the objects of that one backup; trajrl downloads them and checks every
// chunk against its ID and the chunks against the index
// (internal/backupexport). Every other "backup ..." is the entry point's.

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/hanlinai/trajrl-cli/internal/backupexport"
)

func backupCmd(args []string) int {
	if len(args) < 2 || args[1] != "export" {
		return forwardCmd(args)
	}
	const usage = "usage: %s backup export NAME|ID [BACKUP] [-dir DIR] [--json]"
	fs := flag.NewFlagSet(prog+" backup export", flag.ContinueOnError)
	dir := fs.String("dir", "", "where the copy goes (default: ./trajrl-backup-NAME); run again with the same DIR to go on after a stop")
	asJSON := fs.Bool("json", false, "say what was written as JSON")
	var pos []string
	rest := args[2:]
	for {
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		rest = fs.Args()
		if len(rest) == 0 {
			break
		}
		pos, rest = append(pos, rest[0]), rest[1:]
	}
	if len(pos) < 1 || len(pos) > 2 {
		return fail(2, usage, prog)
	}
	target, which := pos[0], ""
	if len(pos) == 2 {
		which = pos[1]
	}
	if strings.ContainsAny(target, " \t'\"") || strings.ContainsAny(which, " \t'\"") {
		return fail(2, usage, prog)
	}
	if *dir == "" {
		*dir = "trajrl-backup-" + target
	}
	c, err := loadConfig()
	if err != nil {
		return fail(255, "%v", err)
	}
	ask := func(_ context.Context, from int, first []string) (*backupexport.Plan, error) {
		a := []string{"backup", "export", target}
		if which != "" {
			a = append(a, which)
		}
		a = append(a, "--json", "--from", strconv.Itoa(from))
		if len(first) > 0 {
			a = append(a, "--first", strings.Join(first, ","))
		}
		out, err := entryOutput(c, a...)
		if err != nil {
			return nil, err
		}
		var p backupexport.Plan
		if err := json.Unmarshal(out, &p); err != nil {
			return nil, fmt.Errorf("the entry point's answer to backup export is not one: %w", err)
		}
		// The newest backup, once named, stays the one fetched.
		if which == "" {
			which = p.Backup
		}
		return &p, nil
	}
	res, err := backupexport.Download(context.Background(), *dir, ask, backupexport.Options{Progress: os.Stderr})
	if err != nil {
		return fail(1, "backup export: %v", err)
	}
	if *asJSON {
		e := json.NewEncoder(os.Stdout)
		e.SetIndent("", "  ")
		e.Encode(res)
		return 0
	}
	abs, _ := filepath.Abs(res.Dir)
	fmt.Printf("%s/%s (%s, %d MiB) is in %s: %d chunks, %d fetched now (%d MiB), every one checked against its ID.\n",
		res.Sandbox, res.Backup, res.DiskFormat, res.DiskBytes>>20, abs, res.Chunks, res.Fetched, res.Bytes>>20)
	if res.Image != "" {
		fmt.Printf("Its lower image: %s (dm-verity checks it against the root hash on your disk when you open it).\n", res.Image)
	}
	fmt.Printf("It is encrypted: only your key opens it. To restore it on any Linux machine with no part of the platform,\n"+
		"follow docs/offline-restore.md from step 1, with /backup = %s, ID=%s, NAME=%s.\n", abs, res.Sandbox, res.Backup)
	return 0
}
