// codesign 실험 보조 바이너리 — 검사 대상이 될 때까지 잠들어 있는다.
// 시스템 실행 파일의 서명 제약을 피하도록 대조군을 직접 빌드한다.
package main

import "time"

func main() { time.Sleep(time.Hour) }
