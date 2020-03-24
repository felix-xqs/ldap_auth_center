package tools

import (
	"testing"
	"time"
)

func TestGetTokenSign(t *testing.T) {
	key1 := "zhangsan"
	key2 := "lisi"

	token, err := GetTokenSign(key1)
	if err != nil {
		t.Log(err)
		return
	}
	t.Log(token)

	token ,err = GetTokenSign(key2)
	if err != nil {
		t.Log(err)
	}
	t.Log(token)

	time.Sleep(2 * time.Second)
	token ,err = GetTokenSign(key2)
	if err != nil {
		t.Log(err)
	}
	t.Log(token)

}
