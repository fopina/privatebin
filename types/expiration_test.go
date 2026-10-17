package types

import "testing"

func TestExpirationValueSet(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "known expiration", input: "1week"},
		{name: "never", input: "never"},
		{name: "unknown expiration", input: "2weeks", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value := ExpirationValue("1day")
			err := value.Set(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Set(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr && value.String() != tt.input {
				t.Fatalf("value = %q, want %q", value, tt.input)
			}
			if tt.wantErr && value != "1day" {
				t.Fatalf("invalid value changed to %q", value)
			}
		})
	}
}
