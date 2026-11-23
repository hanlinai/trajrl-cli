package ownerkey

import "strings"

// Tool is the program whose commands the messages of the owner's tools
// name, for the owner to type as they are printed (#123): "sbxkey", the
// default, or "trajrl", which sets it before it runs anything. The file
// header of ~/.ssh/sbx_known_hosts names sbxkey either way.
var Tool = "sbxkey"

// Command is the command line, under Tool, of sbxkey's command args, for
// example "start web -accept-older 3". trajrl has every command of sbxkey
// under the same words, except init, restore and backup-check, which are
// its "key init", "key restore" and "key backup-check".
func Command(args string) string {
	if Tool != "sbxkey" {
		switch first, _, _ := strings.Cut(args, " "); first {
		case "init", "restore", "backup-check":
			return Tool + " key " + args
		}
	}
	return Tool + " " + args
}

// VerifyOwnerCommand is the command that checks the running sandbox name
// and that it was unlocked with the owner's key: sbxverify's -owner-key
// (the old tools' messages name no sandbox there), or "trajrl verify NAME
// -owner". An empty name is written NAME.
func VerifyOwnerCommand(name string) string {
	if Tool == "sbxkey" {
		return "sbx" + "verify -owner-key"
	}
	if name == "" {
		name = "NAME"
	}
	return Tool + " verify " + name + " -owner"
}
