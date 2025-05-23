package schema

import (
	"reflect"
	"testing"
)

func TestParseComment(t *testing.T) {
	tests := []struct {
		name    string
		comment string
		want    []Section
	}{
		{
			name:    "empty",
			comment: `# @readyOnly`,
			want: []Section{
				{
					Name: "@readyOnly",
				},
			},
		},
		{
			name:    "test0",
			comment: `## ;;; @title "Architecture" @x-enum single="Single";cluster="Cluster Mode"`,
			want: []Section{
				{
					Name:  "@title",
					Value: "Architecture",
					Raw:   `"Architecture" `,
				},
				{
					Name: "@x-enum",
					Options: []Option{
						{Name: "single", Value: "Single"},
						{Name: "cluster", Value: "Cluster Mode"},
					},
					Raw: `single="Single";cluster="Cluster Mode"`,
				},
			},
		},
		{
			name:    "test1",
			comment: `# @enum 8.0.30`,
			want: []Section{
				{
					Name:  "@enum",
					Value: "8.0.30",
					Raw:   "8.0.30",
				},
			},
		},
		{
			name:    "test2",
			comment: `# @description PITR(Point-in-Time Recovery)`,
			want: []Section{
				{
					Name:  "@description",
					Value: "PITR(Point-in-Time",
					Options: []Option{
						{Name: "Recovery)", Value: ""},
					},
					Raw: "PITR(Point-in-Time Recovery)",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseComment(tt.comment)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseComment() got = %#v, want %#v", got, tt.want)
			}
		})
	}
}
