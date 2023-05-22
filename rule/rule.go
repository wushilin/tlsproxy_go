package rule

import (
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
)

type RuleSet struct {
	DefaultAllow        bool
	AllowedStaticHosts  map[string]bool
	RejectedStaticHosts map[string]bool
	AllowedPatterns     []*regexp.Regexp
	RejectedPatterns    []*regexp.Regexp
}

type RuleSetRaw struct {
	NoMatchDecision string   `json:"no_match_decision"`
	Whitelist       []string `json:"whitelist"`
	Blacklist       []string `json:"blacklist"`
}

func (v *RuleSetRaw) generate() (*RuleSet, error) {
	result := RuleSet{
		DefaultAllow:        false,
		AllowedStaticHosts:  make(map[string]bool),
		AllowedPatterns:     make([]*regexp.Regexp, 0),
		RejectedStaticHosts: make(map[string]bool),
		RejectedPatterns:    make([]*regexp.Regexp, 0),
	}
	if strings.ToLower(v.NoMatchDecision) == "accept" || strings.ToLower(v.NoMatchDecision) == "allow" {
		result.DefaultAllow = true
	} else if strings.ToLower(v.NoMatchDecision) == "reject" || strings.ToLower(v.NoMatchDecision) == "deny" {
		result.DefaultAllow = false
	} else if v.NoMatchDecision == "" {
		return nil, errors.New("required field `no_match_decision` not found")
	} else {
		return nil, errors.New("unknown decision [" + v.NoMatchDecision + "] expect allow|reject")
	}

	for _, rule := range v.Whitelist {
		rule = strings.ToLower(rule)
		if strings.HasPrefix(rule, "host:") {
			result.AllowedStaticHosts[rule[5:]] = true
		} else if strings.HasPrefix(rule, "pattern:") {
			pattern := rule[8:]
			if !strings.HasSuffix(pattern, "(?i)") {
				pattern = "(?i)" + pattern
			}
			result.AllowedPatterns = append(result.AllowedPatterns, regexp.MustCompile(pattern))
		} else {
			return nil, errors.New("Unknown rule [" + rule + "] expect to begin with `host:` or `pattern:`")
		}
	}

	for _, rule := range v.Blacklist {
		rule = strings.ToLower(rule)
		if strings.HasPrefix(rule, "host:") {
			result.RejectedStaticHosts[rule[5:]] = true
		} else if strings.HasPrefix(rule, "pattern:") {
			pattern := rule[8:]
			if !strings.HasSuffix(pattern, "(?i)") {
				pattern = "(?i)" + pattern
			}
			result.RejectedPatterns = append(result.RejectedPatterns, regexp.MustCompile(pattern))
		} else {
			return nil, errors.New("Unknown rule [" + rule + "] expect to begin with `host:` or `pattern:`")
		}
	}
	return &result, nil
}
func Parse(file string) (*RuleSet, error) {
	buffer, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	result := &RuleSetRaw{}
	err = json.Unmarshal(buffer, result)
	if err != nil {
		return nil, err
	}
	return result.generate()
}
func (v *RuleSet) CheckAccess(targetHost string) bool {
	if v.DefaultAllow {
		// check for denied hosts
		return !checkMatch(targetHost, v.RejectedStaticHosts, v.RejectedPatterns)
	}

	return checkMatch(targetHost, v.AllowedStaticHosts, v.AllowedPatterns)
}

func checkMatch(host string, static map[string]bool, patterns []*regexp.Regexp) bool {
	host = strings.ToLower(host)
	_, ok := static[host]
	if ok {
		return true
	}
	for _, next := range patterns {
		if next.Match([]byte(host)) {
			return true
		}
	}
	return false
}
