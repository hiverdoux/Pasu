// procinfo 실험의 보조 프로그램: 30초 잠들기만 한다.
// 시스템 실행 파일을 복사하지 않고 직접 빌드해 경로 조회 대조군으로 사용한다.
package main

import "time"

func main() {
	time.Sleep(30 * time.Second)
}
