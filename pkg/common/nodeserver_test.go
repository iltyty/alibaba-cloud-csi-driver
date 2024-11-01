package common

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGetPodStartTime(t *testing.T) {
	tests := []struct {
		name     string
		arg      *v1.Pod
		expected time.Time
		wantErr  bool
	}{
		{
			name: "Pod with start time",
			arg: &v1.Pod{
				Status: v1.PodStatus{
					StartTime: &metav1.Time{Time: time.Unix(100, 0)},
				},
			},
			expected: time.Unix(100, 0),
			wantErr:  false,
		},
		{
			name:     "Pod without start time",
			arg:      &v1.Pod{},
			expected: time.Time{},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := getPodStartTime(tt.arg)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, actual)
			}
		})
	}
}
