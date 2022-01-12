package ruleparser

import (
	"bufio"
	"log"
	"os"
	"strconv"
	"strings"
)

// type ExFilterConfig struct {
// 	Log          ListHead
// 	OutputDir    string
// 	RuleLists    *RuleListNode
// 	NumRuleTypes int
// }

// type RuleType int64

// const (
// 	RULE_TYPE_NONE = 0
// 	RULE_TYPE_LOG
// 	RULE_TYPE_ALERT
// )

// type ListHead struct {
// 	// RLN *RuleListNode
// 	TCPList *RuleTreeNode
// 	RLN     *RuleListNode
// }

// type RuleListNode struct {
// 	RuleList  *ListHead
// 	Mode      RuleType
// 	Rval      int /* 0 == no detection, 1 == detection event */
// 	EvalIndex int /* eval index for this rule set */
// 	Name      string
// 	Next      *RuleListNode
// }

// type OptTreeNode struct {
// 	ChainNodeNumber int
// 	EvalIndex       int
// 	Proto           int
// 	Logto           string /* log file in which to write events which match this rule */
// 	// EventData		Event
// 	OTNActivPtr  *OptTreeNode
// 	RTNActivPtr  *RuleTreeNode
// 	Next         *OptTreeNode
// 	NextSolid    *OptTreeNode
// 	ProtoNodes   **RuleTreeNode
// 	ProtoNodeNum int16
// 	RuleState    int /* enabled or disabled */
// }

// type RuleTreeNode struct {
// 	Right       *RuleTreeNode
// 	Down        *OptTreeNode
// 	ListHead    *ListHead
// 	Type        RuleType
// 	Sip         *IpNode
// 	Dip         *IpNode
// 	Proto       int
// 	OtnRefCount uint
// }

// func CreateDefaultRules(ec *ExFilterConfig) {
// 	CreateRuleType(ec, RULE_TYPE_LOG, 1, &ec.Log)
// }

// func CreateRuleType(ec *ExFilterConfig, mode RuleType, rval int, head *ListHead) *ListHead {
// 	var node RuleListNode
// 	var evalIndex int = 0

// 	if ec == nil {
// 		return nil
// 	}

// 	if ec.RuleLists == nil {
// 		ec.RuleLists = &node
// 	} else {
// 		tmp := ec.RuleLists
// 		var last *RuleListNode
// 		for {
// 			evalIndex += 1
// 			last = tmp
// 			tmp = tmp.Next

// 			if tmp == nil {
// 				break
// 			}
// 		}

// 		last.Next = &node
// 	}

// 	if head == nil {

// 	} else {
// 		node.RuleList = head
// 	}

// 	node.RuleList.RLN = &node
// 	node.Mode = mode
// 	node.Rval = rval
// 	node.EvalIndex = evalIndex

// 	ec.NumRuleTypes += 1

// 	return node.RuleList
// }

// func ParseRule(ec *ExFilterConfig, ruleType RuleType, args string, list *ListHead) {
// 	var toks []string
// 	var protocol int = 0

// 	var rtn RuleTreeNode
// 	var testRtn RuleTreeNode
// 	var otn OptTreeNode
// 	toks = strings.Split(args, "\t")

// 	if len(toks) < 6 {
// 		fmt.Printf("bad rule in rules file : %s", args)
// 		return
// 	}

// 	testRtn.Type = ruleType
// 	protocol = 1
// 	testRtn.Proto = protocol

// 	ProcessIP(ec, toks[1], &testRtn, 0, 0)
// 	ProcessIP(ec, toks[4], &testRtn, 1, 0)
// }

// func ProcessIP(ec *ExFilterConfig, addr string, rtn *RuleTreeNode, mode int, negList int) int {
// 	// rtn.Dip = addr
// 	return 0
// }

// func ProcessHeadNode(ec *ExFilterConfig, rtn RuleTreeNode, list *ListHead) {

// }

var Rules map[uint32]interface{}

// type PortRuleMap map[uint32]map[uint32]map[uint32][]PortRule
type PortRule map[uint32][]string

type RuleOption struct {
	Content string /* string to be matched */
	Message string /* event message to be logged */
}

func ParseRuleFile(filename string) map[string]map[int][]RuleOption {
	var prMap map[string]map[int][]RuleOption = make(map[string]map[int][]RuleOption)

	prMap["dstPortRules"] = make(map[int][]RuleOption)

	var rule string
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		rule = scanner.Text()
		// fmt.Println(rule)

		ParseRule(rule, prMap)

	}

	return prMap
}

func ParseRule(rule string, prMap map[string]map[int][]RuleOption) {
	if strings.HasPrefix(rule, "#") {
		return
	}

	toks := strings.SplitN(rule, " ", 8)

	var dstPort int
	var ruleOption RuleOption
	dstPort, _ = strconv.Atoi(toks[6])
	ruleOptionTmp := parseRuleOptions(toks[7])
	ruleOption.Content = ruleOptionTmp["content"]
	ruleOption.Message = ruleOptionTmp["msg"]
	prMap["dstPortRules"][dstPort] = append(prMap["dstPortRules"][dstPort], ruleOption)

}

func parseRuleOptions(ruleOptionRaw string) map[string]string {
	ruleOptions := strings.TrimPrefix(strings.TrimSuffix(ruleOptionRaw, ")"), "(")

	rulesSlice := strings.Split(ruleOptions, ";")

	var ruleOptionMap map[string]string = make(map[string]string)

	for _, ruleOptRaw := range rulesSlice {
		tmp := strings.Split(ruleOptRaw, ":")
		if len(tmp) < 2 {
			continue
		}
		tmpkey := strings.Trim(tmp[0], " ")
		ruleOptionMap[tmpkey] = strings.TrimPrefix(strings.TrimSuffix(tmp[1], "\""), "\"")
	}

	return ruleOptionMap
}
