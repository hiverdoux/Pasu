package main

import "strings"

// safeText는 로그·알림·승인 창에 표시할 신뢰할 수 없는 문자열에서 ASCII
// 제어문자를 가시적인 이스케이프로 바꾼다. 정상 UTF-8과 공백은 그대로 두고,
// 감사 로그 한 이벤트가 물리적 한 줄이라는 성질을 지킨다.
func safeText(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if c < 0x20 || c == 0x7f {
				const hex = "0123456789ABCDEF"
				b.WriteString(`\x`)
				b.WriteByte(hex[c>>4])
				b.WriteByte(hex[c&0x0f])
			} else {
				b.WriteByte(c)
			}
		}
	}
	return b.String()
}
