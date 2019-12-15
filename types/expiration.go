package types

import (
	"fmt"
	"strings"
)

type ExpirationValue string

var expirationValues = []string{
	"5min",
	"10min",
	"1hour",
	"1day",
	"1week",
	"1month",
	"1year",
	"never",
}

func (v *ExpirationValue) Get() interface{} {
	return ExpirationValue(*v)
}

func (v *ExpirationValue) Set(s string) error {
	for _, k := range expirationValues {
		if k == s {
			*v = ExpirationValue(s)
			return nil
		}
	}
	return fmt.Errorf("valid options - %v", strings.Join(expirationValues, ","))
}

func (v *ExpirationValue) String() string {
	return string(*v)
}

func (v *ExpirationValue) Type() string {
	return "string"
}
