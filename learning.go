package main

import (
	"fmt"
	"sort"
)

var global = 5

func learn_array() {
	//init
	var i = make([]int, 5, 5)
	//declare
	var k [5]int
	//declare with value
	var c = []int{1, 2, 3, 4, 5}
	//print with subscription
	var d = 1 << 32
	fmt.Print(c[len(c)-1], d<<30 > (1<<31))
	global = 6
	fmt.Print(global)
	fmt.Print(i, k, c)

	a2darr := [][]int{
		{1, 2},
		{2, 3},
	}

	for _, v := range a2darr {
		for _, k := range v {
			fmt.Print(k)
		}
	}

}

type By func(p1, p2 []int) bool
type intervalSorter struct {
	interval [][]int
	by       func(p1, p2 []int) bool
}

func (s *intervalSorter) Len() int {
	return len(s.interval)
}

func (s *intervalSorter) Swap(i, j int) {
	s.interval[i], s.interval[j] = s.interval[j], s.interval[i]
}

func (s *intervalSorter) Less(i, j int) bool {
	return s.by(s.interval[i], s.interval[j])
}

func (by By) Sort(intervals [][]int) {
	is := &intervalSorter{
		interval: intervals,
		by:       by,
	}
	sort.Sort(is)

}

func learning_sort() {
	intervals := [][]int{
		{1, 5},
		{2, 4},
		{3, 7},
		{2, 6},
	}
	is := func(p1, p2 []int) bool {
		if p1[0] == p2[0] {
			return p2[1] < p1[1]
		}
		return p1[0] < p2[0]
	}
	By(is).Sort(intervals)
	fmt.Print(intervals)
}

func main() {
	/*
		arr := []int{1, 2, 3, 4}
		for i, v := range arr {
			fmt.Print(i, v)
		}
	*/
	//learn_array()
	learning_sort()
	fmt.Print(global)
}
