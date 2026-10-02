# 작업 인수인계 (HANDOFF)

이 문서는 **메모리가 없는 새 Claude 세션이 이 작업을 이어받기 위한 것**입니다.
작업자는 비개발자이므로, 설명은 개념 위주로 하고 명령어는 그대로 복사해 쓸 수 있게 제시할 것.

> 이 파일은 작업 브랜치에서만 쓰는 메모입니다. upstream PR 브랜치(`unpin-version-green-icon`)에는
> 이미 빠져 있으니, 작업 브랜치에서는 지우지 말 것.

## 0. 지금 상태 (2026-10-02 기준) — 새 세션은 여기부터

1. **upstream PR [#10](https://github.com/hubeen/dual-kakaotalk-macos/pull/10)을 보내고 원 제작자 답을 기다리는 중.**
   2026-10-02 기준 댓글·리뷰 0개, upstream `main`은 여전히 `91829b7`.
2. 코드 작업은 끝났음. 실기기 설치, Dock 아이콘 초록색, CI(`swift test` 35개, Universal 빌드) 모두 확인됨(6절).
3. 새 세션이 처음 할 일:
   ```bash
   gh pr view 10 -R hubeen/dual-kakaotalk-macos --comments
   gh api 'repos/hubeen/dual-kakaotalk-macos/commits?per_page=3' --jq '.[] | "\(.sha[0:7]) \(.commit.message | split("\n")[0])"'
   ```
   - 수정 요청이 왔으면 → 7절 2번 절차대로 PR 브랜치에 반영.
   - 병합됐으면 → 작업 브랜치를 upstream에 맞춰 정리하고, 사이트 유틸리티 카드는 upstream 릴리스로 연결(7절 2번).
   - ~2026-10-22까지 무응답·거절이면 → 2안(직접 배포)을 사용자에게 제안. 결정은 사용자 몫.
4. **사용자 작업 규칙** (전역 `~/.codex/AGENTS.md` — 로컬 세션이면 자동으로 읽힘):
   - 코드·문서 수정 전에 **계획(파일, 근본 원인, 접근법)을 먼저 보여주고**, 사용자가 "진행해"/"가자"라고
     한 뒤에만 수정.
   - PR 전송, 남의 저장소 작업, 저장소 이전 같은 **외부 공개 작업은 건별로 따로 확인.**
   - 코드 저장소는 `easpera-com` 조직 소유. 유료 결제(예: Apple Developer $99)는 실행하지 말고 알리기만.

## 1. 한 줄 요약

`hubeen/dual-kakaotalk-macos`(맥에서 카카오톡 2개 동시 실행) 를 포크해서 **두 가지를 고쳤고,
실기기 설치·Dock 아이콘 확인·CI 검증을 마친 뒤 upstream에 PR을 보낸 상태**입니다.

## 2. 배경 — 왜 이 작업을 했나

1. 원 저장소는 공식 `/Applications/KakaoTalk.app`을 복사해 번들 ID를 바꾼
   `/Applications/KakaoTalkWork.app`을 만들어 둘을 동시에 실행하게 해 줍니다.
   macOS가 앱 데이터를 번들 ID 기준으로 분리 보관하기 때문에 계정 2개를 쓸 수 있습니다.
2. 사용자가 요청한 것은 두 가지였습니다.
   - **요청 1** — 카카오톡이 앱스토어에서 업데이트돼도 **설치 프로그램을 새로 받지 않고**
     이미 받아 둔 `Install.command`만 다시 실행하면 되게 할 것. (자동 업데이트가 아니라,
     원 저장소가 원래 요구하는 "업데이트 후 재실행" 방식을 그대로 유지)
   - **요청 2** — 듀얼 앱의 **앱 아이콘 배경**을 초록색으로 바꿔 Dock에서 구분되게 할 것.
     (원 저장소는 메뉴 막대 아이콘만 초록색으로 바꾸고, 앱 아이콘은 이름으로만 구분했음)

## 3. 무엇을 바꿨나

브랜치: `claude/trusting-mayer-9tk94o` (포크 `easpera-com/dual-kakaotalk-macos` — 2026-10-01 `trialismm`에서 이전, 옛 주소는 자동 연결됨)
기준 커밋: `91829b7` (upstream `hubeen/dual-kakaotalk-macos`의 "Support KakaoTalk 26.8.0")

| 커밋 | 내용 |
| --- | --- |
| `262196e` | 요청 1·2의 본체. 버전 고정 제거 + 앱 아이콘 초록색 |
| `0e42487` | 배포 아티팩트 버전 표기를 `Install.command`와 일치 (`0.2.0-beta.1`) |
| `0a823c8` | 배포 스크립트가 빌드 결과물을 못 찾던 문제 수정 + `DUAL_KAKAOTALK_ARCHS` 추가 |
| `e0c4d30` | "변경 없음" 판정에 아이콘 비교 추가 (색만 바꿔 재설치해도 건너뛰지 않게) |
| `86c11ec` | CI 업로드 경로를 버전 패턴으로 (`v0.1.0-beta.21` 고정이라 실패하던 것) |
| `9aa5ada` | 경계 픽셀 검사를 초록 채널 대신 색조로 판정 (6절 6번) |

이 밖의 커밋은 전부 `HANDOFF.md` 갱신. PR 브랜치 `unpin-version-green-icon`에는 위 6개만
(해시는 다름) 들어 있음.

### 3-1. 요청 1 — 버전 고정 제거

1. `Sources/DualKakaoTalkCore/OfficialAppInspector.swift`
   - **삭제**: `expectedShortVersion = "26.8.0"`, `expectedBuildVersion = "2000"` 하드코딩.
     이 값과 정확히 일치하지 않으면 설치를 거부했기 때문에, 카카오톡이 업데이트될 때마다
     저장소 관리자가 새 릴리스를 내기 전에는 재설치조차 불가능했음.
   - **대체**: 번들 ID(`com.kakao.KakaoTalkMac`), 카카오 Team ID(`L75WVXX68A`),
     `codesign --verify`, 그리고 `minimumShortVersion = "26.6.1"` 하한선만 검증.
   - `isVersion(_:atLeast:)` 추가. **파싱 불가능한 버전 문자열은 통과시킴** — 신원과 서명이
     실제 관문이고, 카카오가 버전 표기 형식을 바꿔도 설치가 죽으면 안 되기 때문.
2. `Install.command`
   - `Assets.car` 지문이 목록에 없으면 `exit 1` 하던 부분을 **안내 메시지로 강등**.
     이제 메뉴 막대 아이콘 단계만 건너뛰고 설치는 계속됨.
   - `INSTALLER_VERSION`을 `0.2.0-beta.1`로.

### 3-2. 요청 2 — 앱 아이콘 초록색

1. `Sources/DualKakaoTalkCore/AppIconRecolorer.swift` (신규, 약 300줄)
   - 번들의 `.icns`를 읽어 → 크기별로 렌더 → **노란 배경만 초록색으로 색조 회전** →
     `/usr/bin/iconutil`로 `.icns` 재생성 → staged copy 안에서만 교체.
   - **공개 AppKit만 사용.** 비공개 API도 지문 허용 목록도 쓰지 않으므로 카카오톡 버전과 무관하게 동작.
2. 색 결정
   - 목표 색조는 기존 브랜드 그린 `#5B8A72`의 색조(149.4°)에서 가져옴 — 두 아이콘이 한 제품으로 읽히게.
   - `saturationCap = 0.75`, `luminanceScale = 0.75` → 최종 배경색 **`#32C67A`**.
   - 이 두 상수가 **색 조정용 손잡이**입니다. 올리면 밝고 쨍하게, 내리면 어둡고 차분하게.
     (상한 없이 광도를 보존하면 `#40FF9D` 같은 형광 초록이 나와서 두 상수를 넣은 것)
   - 보존되는 것: 갈색 말풍선(색조 0°), 흰색·검정(채도 낮음), 알림 빨강. 음영/하이라이트는 밝기 순서 유지.
3. `Sources/DualKakaoTalkCore/Installer.swift`
   - `mutateAndSign`이 `Bool`(메뉴 아이콘 변경 여부)을 반환. `prepare`는 `PreparedInstall` 구조체 반환.
   - **핵심 설계 원칙**: 단계를 두 종류로 분리.
     - **필수(실패 시 설치 중단)** — 복제, 번들 ID/실행파일 변경, 표시 이름, **앱 아이콘 색 변경**, ad-hoc 서명
     - **선택(실패 시 건너뜀)** — 메뉴 막대 아이콘(비공개 CoreUI + 지문 허용 목록 필요)
   - 보안 검증은 fail-closed, 외형 기능은 fail-open. 이 구분을 깨뜨리지 말 것.
4. 부수 변경
   - `ColorTransformer.swift`에 `unpremultiply`/`premultiply`를 공용 함수로 올리고
     `AssetCatalogPatcher.swift`의 중복 정의 제거.
   - `main.swift`의 `prepare-install`은 **stdout에 경로만** 출력(셸이 파싱함),
     메뉴 아이콘 여부는 stderr에 `diagnostic.menu_bar_icons_recolored=...`로.
   - 테스트: `Tests/.../AppIconRecolorerTests.swift` 신규, `OfficialAppInspectorTests.swift` 갱신.
   - 문서: `README.md`, `README.en.md`, `Docs/FEASIBILITY.md`, `Docs/FEASIBILITY.en.md` 갱신.

### 3-3. 빌드 스크립트 수정 (`0a823c8`)

1. `Scripts/build-release.sh`가 `<scratch>/<triple>/release/...` 고정 경로를 가정했는데,
   최신 SwiftPM은 `<scratch>/out/Products`에 씀 → "expected build output is absent" 실패.
   → `swift build --show-bin-path`로 물어보고, 실패 시 탐색하도록 변경.
2. `DUAL_KAKAOTALK_ARCHS` 환경변수 추가. 기본값은 `x86_64 arm64`(Universal, 릴리스용).
   최신 macOS의 Command Line Tools에는 x86_64 Swift 런타임이 없어 교차 컴파일이 안 되므로,
   **본인 맥용으로만 빌드할 때 `DUAL_KAKAOTALK_ARCHS=arm64`를 씀.**

## 4. 작업자 환경 (중요 — 제약이 있음)

1. 맥: **Apple Silicon**, **macOS 27**, 사용자 홈 `/Users/sungmoonjung`
2. **Xcode가 설치돼 있지 않고 Command Line Tools만 있음.**
   → `XCTest`가 없어서 **`swift test`는 실행 불가.** 이건 환경 문제이지 코드 문제가 아님.
   → 새 세션에서 `swift test` 실패 로그를 보면 이 사실을 먼저 떠올릴 것.
   → 대신 **GitHub Actions(`macos-14`, Xcode 있음)** 가 `swift test`와 Universal 빌드를 돌림.
     브랜치에 push하면 자동 실행되고, 결과는 `gh run list -R easpera-com/dual-kakaotalk-macos`로 확인.
3. 빌드 로그의 `ld: warning: search path ... not found`는 Xcode 미설치로 인한 정상 경고. 무시.
4. 저장소 위치: **`~/Projects/dual-kakaotalk-macos`** (2026-10-01 확인. 원래는 `~/dual-kakaotalk-macos`였음)
5. `gh` CLI가 로그인돼 있고, 사용자는 `easpera-com` 조직의 admin.
6. 카카오톡 본체는 **Mac App Store 설치본**. 맥용 카카오톡은 사실상 앱스토어 단일 채널.

## 5. 재현 명령 (그대로 복사 가능)

```bash
cd ~/Projects/dual-kakaotalk-macos
git pull

# 코드가 컴파일되는지 (swift test는 이 맥에서 불가)
swift build

# 설치 파일 묶음 만들기 (이 맥은 arm64 전용으로 빌드해야 함)
DUAL_KAKAOTALK_ARCHS=arm64 ./Scripts/build-release.sh

# 아무것도 바꾸지 않는 진단 — 현재 카카오톡이 검사를 통과하는지만 확인
./dist/Dual-KakaoTalk-for-macOS/bin/dual-kakaotalk-tool inspect

# 설치 (카카오톡 두 개 모두 종료 후, 관리자 인증 필요)
./dist/Dual-KakaoTalk-for-macOS/Install.command
```

## 6. 검증 상태

### 검증 완료
1. `swift build` 성공 — 작성한 코드가 정상 컴파일됨.
2. `DUAL_KAKAOTALK_ARCHS=arm64 ./Scripts/build-release.sh` 성공.
   아티팩트 SHA-256 `89b98169c522fd00d92b3390cb9227d0dc04326f9b6cad633957ab4cb3a87f89`
   (`Dual-KakaoTalk-for-macOS-v0.2.0-beta.1.zip`, arm64 전용 빌드).
   코드 서명 검증, `verify-no-kakao-assets.sh` 모두 통과.
3. `Install.command` 실행 → **설치 성공.** 사용자가 "잘 된 것 같다"고 확인.
4. 색 변환 알고리즘 — 개발 환경이 리눅스라 macOS 렌더링을 볼 수 없어서,
   동일 알고리즘을 파이썬으로 포팅해 수치로 검증함
   (`#FAE100 → #32C67A`, 말풍선/흰색/검정/알림빨강 불변, 음영 밝기 순서 유지).
5. **Dock과 `⌘Tab` 전환기에서 앱 아이콘이 초록색으로 보임** — 2026-10-01 사용자가 실기기에서 확인.
   카카오톡이 실행 중 `NSApplication.applicationIconImage`로 아이콘을 덮어쓰지 않는다는 뜻.
   원 저장소는 Dock 아이콘 새로고침 시도를 되돌린 이력이 있음(`fa7c90d`, `f245951`) —
   번들 `.icns` 자체를 바꾸는 이 방식은 그 문제를 겪지 않음.
6. **`swift test` 35개 전부 통과 + Universal(`x86_64` + `arm64`) 릴리스 빌드 성공** — 2026-10-01 CI
   ([실행 기록](https://github.com/easpera-com/dual-kakaotalk-macos/actions/runs/36863382141)).
   첫 실행에서 `testAntialiasedEdgePixelsArePartiallyShifted` 1개가 실패했는데, 코드가 아니라 검사 기준 문제였음:
   `luminanceScale = 0.75`로 일부러 어둡게 하므로 경계 픽셀의 초록 채널은 128 → 128로 그대로이고
   색조만 31.6° → 61.8°로 이동함. 초록 채널 대신 색조로 판정하도록 고침(`9aa5ada`).

### 미검증 — 새 세션이 이어받을 부분
1. Intel 실기기 실행 — 빌드에 `x86_64`는 포함되지만 인텔 맥에서 돌려 본 적은 없음.
2. 다음 카카오톡 업데이트 후 `Install.command` 재실행이 실제로 통과하는지 — **요청 1의 유일한 실전 확인.**
   설치 당시 사용자의 카카오톡은 **26.8.0 (2000)**, 즉 예전 고정값과 같은 버전이었음
   (설치 로그 `diagnostic.kakao_version=26.8.0`, `diagnostic.menu_bar_icons_recolored=true`).
   그래서 메뉴 막대 아이콘도 지문이 일치해 초록색으로 적용됐고, 버전 고정 제거 경로는
   아직 실기기에서 한 번도 타지 않았음 — 버전 비교 로직은 단위 테스트로만 검증됨.
   다음 업데이트 후에는 메뉴 막대 아이콘 단계만 건너뛰고 설치가 통과하는 것이 정상.

## 7. 이어서 할 만한 일

1. **아이콘 색 튜닝** — 사용자가 농도를 바꾸고 싶다고 하면
   `AppIconRecolorer.swift`의 `saturationCap`, `luminanceScale` 두 값만 조정하고 재빌드 후 재설치.
   (설치 프로그램의 "변경 없음" 판정은 `Assets.car`뿐 아니라 아이콘 파일도 비교하므로,
   아이콘만 바뀌어도 재설치가 정상 진행됨 — `installedIconMatchesStaged` 참고)
2. **upstream PR — 2026-10-01 보냄:** [hubeen/dual-kakaotalk-macos#10](https://github.com/hubeen/dual-kakaotalk-macos/pull/10).
   - PR 브랜치는 `unpin-version-green-icon`. upstream `91829b7`에서 이 브랜치의 커밋을 cherry-pick하되
     `HANDOFF.md`를 빼고, 커밋 메시지의 `Claude-Session:` 줄을 지운 것. 코드는 작업 브랜치와 동일.
   - 원 제작자가 수정을 요청하면 **PR 브랜치에 커밋**하고 같은 변경을 작업 브랜치에도 반영할 것.
   - 배경: 사용자는 easpera.com에 '유틸리티 모음'을 만들 계획. 사이트는 링크만 걸고, PR이 받아들여지면
     **원 저장소 릴리스로 연결**하는 것이 1안. 2~3주(~2026-10-22) 무응답·거절이면
     `easpera-com/dual-kakaotalk-macos`에서 직접 릴리스하는 것이 2안 — 이때는 `Install.command`·
     `Uninstall.command`의 이슈 링크와 README 다운로드 링크를 이 저장소로 바꿔야 함.
3. **자동 업데이트** — 사용자가 원하면. 설계는 이미 검토함:
   감시용 LaunchAgent + `~/Applications` 설치(관리자 인증 불필요) + 자체 서명 인증서로 신원 고정
   (ad-hoc 서명은 갱신마다 신원이 바뀌어 알림·권한이 재요청될 수 있음).
   단 원 저장소는 "백그라운드 감시 프로그램을 설치하지 않는다"를 명시적 설계 원칙으로 두고 있음.

## 8. 반드시 유지해야 할 제약

1. **카카오 자산을 저장소나 릴리스에 절대 포함하지 말 것.** 모든 픽셀은 사용자 맥에서 설치 시점에
   파생시킴. `Scripts/verify-no-kakao-assets.sh`가 이를 강제하며, `.icns`/`.png`/`.car` 커밋을 막음.
   이것이 이 프로젝트의 법적 방어선.
2. **필수/선택 단계 구분을 지킬 것** (3-2의 3번 참고). 외형 기능이 설치 전체를 인질로 잡지 않게.
3. **권한 있는 설치 경로의 검증을 약화시키지 말 것.** `PrivilegedInstallRequest`의 고정 문법,
   digest 재확인, 잠금, write-ahead 저널은 원 저장소의 보안 설계이며 이번 작업에서 건드리지 않았음.
4. `prepare-install`의 **stdout은 경로 한 줄만** 유지. `Install.command`가 그걸 파싱함.

## 9. 사업적 맥락 (사용자가 다시 물어볼 수 있음)

이전 세션에서 "이걸 제품으로 팔 수 있나"를 조사해 **기술적으로는 가능하나 사업으로는 비추천**이라고
답했습니다. 근거를 요약하면:

1. 카카오톡 운영정책(2025-09-30 시행)은 허용되지 않은 방법의 서비스 이용 시
   **계정 이용을 한시적·영구적으로 제한**할 수 있다고 명시. 피해가 판매자가 아니라 **고객 계정**에 감.
2. 맥용 카카오톡은 앱스토어 배포이고, 앱스토어 영수증은 번들 ID·버전·기기에 묶임.
   카카오가 영수증 검증을 강화하면 **제품이 즉시 무력화**됨.
3. 우리 설치 프로그램은 다른 앱을 수정하므로 **Mac App Store 판매가 구조적으로 불가**.
   직접 배포 + Developer ID 공증(연 $99)이 필요.
4. 권고: 무료 오픈소스로 유지하며 기술 증명 자산으로 쓰는 편이 기댓값이 높음.
5. 실사용 주의: **두 앱은 서로 다른 계정으로 쓸 것.** 같은 계정을 여러 클라이언트에 반복 인증하면
   비정상 접속으로 감지될 수 있음.

## 10. 새 세션 부트스트랩

세션 종류에 따라 다름. 먼저 `pwd`와 `uname`으로 어느 쪽인지 확인할 것.

### A. 사용자 맥에서 도는 로컬 세션 (권장 — 2026-10-01 세션이 이 방식)
1. 작업 폴더 `~/Projects/dual-kakaotalk-macos`에서 시작. `add_repo` 불필요.
2. `swift build`, `build-release.sh`(arm64), `gh` 모두 직접 실행 가능. `swift test`만 불가(4절 2번) → CI 사용.
3. 전역 규칙(`~/.codex/AGENTS.md`)과 이 프로젝트의 Claude 메모리가 자동으로 읽힘.

### B. 클라우드(리눅스) 세션
1. 이 저장소를 세션에 붙여야 함: `add_repo` 로 `easpera-com/dual-kakaotalk-macos` (access: `push`).
   `add_repo`는 세션에 이미 붙은 저장소와 **같은 소유자만** 추가 가능 — 이미 붙은 저장소가
   `trialismm` 소유라면 거부될 수 있으니, 그때는 `easpera-com` 소유 저장소에서 세션을 시작할 것.
   upstream(`hubeen/...`)은 추가 불가.
2. 리눅스라 Swift 툴체인도 AppKit도 없음. **코드 작성·리뷰만 가능**하고, 검증은 push 후 CI로,
   설치·실행은 사용자 맥에서. 순수 계산 로직은 파이썬으로 포팅해 검증하는 방법이 유효했음.
3. 전역 규칙 파일이 없으므로 0절 4번의 작업 규칙을 직접 따를 것.
