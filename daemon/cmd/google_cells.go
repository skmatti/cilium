package cmd

import "github.com/cilium/cilium/pkg/hive/cell"

var googleCell = cell.Module(
	"google",
	"Google",
)
