package ruleparser

type IPSTOREMODES int64

const (
	SFIP_LIST = 0
	SFIP_TABLE
)

type IpNode struct {
	Ip   *uint32
	Next *IpNode
}
