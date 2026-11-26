package ui

import (
	"strings"
	"testing"
)

// tree fills the screen's memory of the last tree from row names written as
// paths: a row hangs under the row whose name is its own without the last
// part. (The screen itself never reads a path: it gets the parents.)
func tree(u *UI, paths ...string) {
	u.treeAll, u.treeUp, u.treeKids = paths, make([]int, len(paths)), nil
	for i, p := range paths {
		u.treeUp[i] = -1
		if k := strings.LastIndex(p, ">"); k >= 0 {
			for j, q := range paths {
				if q == p[:k] {
					u.treeUp[i] = j
				}
			}
		}
	}
	for i, p := range paths {
		for _, up := range u.treeUp {
			if up == i {
				u.treeKids = append(u.treeKids, p)
				break
			}
		}
	}
}

// Opening a folded hop opens the chain below it down to the next fork:
// 5 → 6-9 → DST → {S1, S2}: Enter on 5 shows 6-9, DST and both servers;
// the fork's own children (folded subtrees) stay as they were.
func TestUnfoldChain(t *testing.T) {
	u := &UI{folded: map[string]bool{}}
	tree(u, "1", "1>5", "1>5>6", "1>5>6>D", "1>5>6>D>S1", "1>5>6>D>S1>x", "1>5>6>D>S2", "1>7")
	for _, p := range u.treeKids {
		u.folded[p] = true
	}
	u.unfoldChain("1>5")
	for _, p := range []string{"1>5", "1>5>6", "1>5>6>D"} {
		if u.folded[p] {
			t.Fatalf("%s still folded", p)
		}
	}
	if !u.folded["1>5>6>D>S1"] || !u.folded["1"] {
		t.Fatal("chain opened past the fork or above the node")
	}
	// a fork itself: only that node opens
	u.folded["1"] = true
	u.unfoldChain("1")
	if u.folded["1"] || u.folded["1>5"] {
		t.Fatalf("fork: %v", u.folded)
	}
}

// '*' keeps every fork open and folds each part that no longer branches at
// its top: one line per route.
func TestFoldToRoutes(t *testing.T) {
	u := &UI{folded: map[string]bool{"1": true}}
	tree(u, "1", "1>2", "1>2>4", "1>2>4>5", "1>2>4>5>D", "1>2>6", "1>2>6>7", "1>2>6>7>D", "1>3", "1>3>8", "1>3>8>D")
	u.foldToRoutes()
	want := map[string]bool{"1>2>4": true, "1>2>6": true, "1>3": true}
	if len(u.folded) != len(want) {
		t.Fatalf("folded %v, want %v", u.folded, want)
	}
	for p := range want {
		if !u.folded[p] {
			t.Fatalf("folded %v, want %v", u.folded, want)
		}
	}
	// a single route: one line
	tree(u, "1", "1>2", "1>2>D")
	u.foldToRoutes()
	if len(u.folded) != 1 || !u.folded["1"] {
		t.Fatalf("single route: %v", u.folded)
	}
}

// A run of hops that never answer is one row whose name is several parts
// longer than its parent's ("a>*>*>b" under "a"). It is still a child of
// "a": the chain opens through it and '*' sees the fork below it.
func TestFoldAcrossCollapsedRows(t *testing.T) {
	u := &UI{folded: map[string]bool{}}
	u.treeAll = []string{"a", "a>*>*", "a>*>*>b", "a>*>*>b>D1", "a>*>*>c", "a>*>*>c>D2"}
	u.treeUp = []int{-1, 0, 1, 2, 1, 4}
	u.treeKids = []string{"a", "a>*>*", "a>*>*>b", "a>*>*>c"}
	for _, p := range u.treeKids {
		u.folded[p] = true
	}
	u.unfoldChain("a")
	if u.folded["a"] || u.folded["a>*>*"] {
		t.Fatalf("the chain did not open through the row of silent hops: %v", u.folded)
	}
	if !u.folded["a>*>*>b"] || !u.folded["a>*>*>c"] {
		t.Fatalf("the chain opened past the fork: %v", u.folded)
	}
	u.foldToRoutes()
	if len(u.folded) != 2 || !u.folded["a>*>*>b"] || !u.folded["a>*>*>c"] {
		t.Fatalf("one line per route below the fork, got %v", u.folded)
	}
}
