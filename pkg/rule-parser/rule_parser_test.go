package ruleparser

import (
	"fmt"
	"testing"
)

func TestParseRuleFile(t *testing.T) {
	prMap := ParseRuleFile("rules/example.rules")
	fmt.Println(prMap)
}
