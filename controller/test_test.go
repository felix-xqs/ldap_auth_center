package controller

import (
	"testing"
)

func TestOne(t *testing.T){
	s := "dsdasd"
	arr := make([]int,256)
	for i := 0; i < len(s);i++{
		arr[s[i]] = i
		t.Log(s[i],arr[s[i]])
	}
	t.Log(arr)
}
