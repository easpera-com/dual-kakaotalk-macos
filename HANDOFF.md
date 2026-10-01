# 작업 인수인계 (HANDOFF)

이 문서는 **메모리가 없는 새 Claude 세션이 이 작업을 이어받기 위한 것**입니다.
작업자는 비개발자이므로, 설명은 개념 위주로 하고 명령어는 그대로 복사해 쓸 수 있게 제시할 것.

> 이 파일은 이 포크에서만 쓰는 작업 메모입니다. 원 저장소(upstream)에 PR을 보낼 때는 먼저 삭제할 것.

## 1. 한 줄 요약

`hubeen/dual-kakaotalk-macos`(맥에서 카카오톡 2개 동시 실행) 를 포크해서 **두 가지를 고쳤고,
실기기 빌드·설치와 Dock 아이콘 색 육안 확인까지 마친 상태**입니다. 남은 것은 선택적 튜닝과 배포 준비뿐입니다.

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

브랜치: `claude/trusting-mayer-9tk94o` (포크 `trialismm/dual-kakaotalk-macos`)
기준 커밋: `91829b7` (upstream `hubeen/dual-kakaotalk-macos`의 "Support KakaoTalk 26.8.0")

| 커밋 | 내용 |
| --- | --- |
| `262196e` | 요청 1·2의 본체. 버전 고정 제거 + 앱 아이콘 초록색 |
| `0e42487` | 배포 아티팩트 버전 표기를 `Install.command`와 일치 (`0.2.0-beta.1`) |
| `0a823c8` | 배포 스크립트가 빌드 결과물을 못 찾던 문제 수정 + `DUAL_KAKAOTALK_ARCHS` 추가 |

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
3. 빌드 로그의 `ld: warning: search path ... not found`는 Xcode 미설치로 인한 정상 경고. 무시.
4. 저장소 위치: 원래 `~/dual-kakaotalk-macos`. 사용자가 `~/Projects/` 아래로 옮겼을 수 있음 —
   작업 전에 실제 경로를 물어볼 것. (폴더를 옮겨도 동작에는 문제 없음을 이미 확인·안내했음)
5. 카카오톡 본체는 **Mac App Store 설치본**. 맥용 카카오톡은 사실상 앱스토어 단일 채널.

## 5. 재현 명령 (그대로 복사 가능)

```bash
cd ~/dual-kakaotalk-macos          # 또는 사용자가 옮긴 경로
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

### 미검증 — 새 세션이 이어받을 부분
1. `swift test` — XCTest가 없어 미실행. Xcode 설치 시에만 가능(용량 10GB+, 급하지 않음).
2. Universal(x86_64 포함) 빌드 — 이 맥에서는 불가. 배포하려면 다른 환경 필요.
3. 메뉴 막대 초록 아이콘 — 사용자의 카카오톡 버전이 지문 목록(26.8.0)과 달라 건너뛰었을 가능성 높음.
   **이건 정상 동작**이며, 오히려 요청 1이 작동한다는 증거.
4. 다음 카카오톡 업데이트 후 `Install.command` 재실행이 실제로 통과하는지 — 요청 1의 최종 확인.

## 7. 이어서 할 만한 일

1. **아이콘 색 튜닝** — 사용자가 농도를 바꾸고 싶다고 하면
   `AppIconRecolorer.swift`의 `saturationCap`, `luminanceScale` 두 값만 조정하고 재빌드 후 재설치.
   (설치 프로그램의 "변경 없음" 판정은 `Assets.car`뿐 아니라 아이콘 파일도 비교하므로,
   아이콘만 바뀌어도 재설치가 정상 진행됨 — `installedIconMatchesStaged` 참고)
2. **upstream PR** — `hubeen/dual-kakaotalk-macos`에 기여할지 사용자에게 확인.
   보낼 경우 이 `HANDOFF.md`를 먼저 삭제할 것.
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

1. 새 세션의 기본 작업 폴더는 `raycast-keychain`(**무관한 별개 프로젝트**)일 수 있음.
   이 저장소를 세션에 붙여야 함: `add_repo` 로 `trialismm/dual-kakaotalk-macos` (access: `push`).
2. **주의**: `add_repo`는 세션에 이미 붙은 저장소와 **같은 소유자만** 추가 가능.
   `trialismm` 소유이므로 문제없음. 반대로 upstream(`hubeen/...`)은 추가 불가이며,
   그 때문에 이전 세션에서는 포크를 사용자가 직접 만들어야 했음.
3. 개발 컨테이너는 **리눅스**라 Swift 툴체인도 AppKit도 없음.
   **코드 작성과 리뷰까지만 가능하고, 컴파일·테스트·실행은 전부 사용자 맥에서 해야 함.**
   순수 계산 로직은 파이썬으로 포팅해 검증하는 방법이 유효했음.
