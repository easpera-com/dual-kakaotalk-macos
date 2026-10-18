#!/usr/bin/env node
// PreToolUse 훅 — 비밀값 파일(.env*), 1Password 값, 프로젝트 문서(_core/, 옮기기 전은 _private/)의 원본과 폴더를 코드로 지킨다. 부탁이 아니라 차단이다.
// 위험한 git push(기본 가지로 · 보낼 가지를 풀 수 없는 · 광역)는 사람에게 묻고 강제 push(-f · --force · +가지)는 막는다 — 작업 가지 push는 설정의 allow(`Bash(git push *)`)가
// 묻지 않게 하고 여기서 위험한 꼴만 거른다. 이름 없는 push(`git push`)는 지금 가지와 @{push} 로 풀어 작업 가지면 통과한다(v35).
// 커밋 전 검사의 통과 기록(check-once-passed)은 손으로 쓰지 못하게 막는다(2026-10-17 R-224).
// 공통 규칙 0(main push 승인)·3(비밀값)·8(_core·_private)과 ~/.codex/procedures/secrets.md(1Password)의 강제 장치다. project-setting 스킬의 틀(templates/claude-guard)에서 왔고,
// jarvis 프로젝트의 가드 훅을 바탕으로 프로젝트에 묶인 규칙을 뺐다. 이 파일은 고치지 않는다 — 프로젝트 전용 규칙은
// .claude/hooks/guard.local.mjs에 두면 같은 입력으로 불러 더 엄한 쪽을 따른다(withLocal, 2026-10-12).
//
// settings.json의 deny 규칙은 예외를 둘 수 없다(.env.example·.env.op는 읽어야 한다). 그래서 판정은 여기서 한다.
// 명령 문자열만 본다 — 스크립트가 안에서 값을 찍는 것은 output-scan.mjs가 출력에서 잡아 알린다.
// 명령 문자열은 셸처럼 나눠 본다(splitCommands — 따옴표 · $'…' · 줄 이음(\ + 줄바꿈) · 주석 · heredoc · 명령 치환). 셸에 넘긴 글(bash · sh · zsh · dash · ksh …의
// -c, 셸이 받는 heredoc 본문)도 다시 나눠 본다. 셸마다 갈리는 곳($'…' · $"…")은 두 꼴로 나눠 더 엄한 쪽을 따른다(splitModes, 2026-10-13).
// 커밋 전 검사 우회(5)와 위험한 git 명령(6 — push · 가지 지우기 · 기본 가지 커밋 · 무시된 파일 지우기)은 셸이 명령에 넘기는 인자 그대로 나눈 꼴
// (argvModes — 치환 자리를 이어 쓰고 입력 리디렉션 · here-string 을 뺌)도 본다(2026-10-13 4차).
// Claude Code(.claude/settings.json)와 Codex(.codex/hooks.json, GUARD_CLIENT=codex — 물음은 거부로)가 같은 사본을 부른다. 셸 도구는 Bash 와 Monitor ·
// Codex 의 셸 도구를 같게 본다(SHELL_TOOLS, v35).
//
// v35(2026-10-18 재설계 W-006 R-265): 세션의 자리(seat — Paseo 밖 · 단독 · 팀원 · 서브에이전트 · agy · 모름)를 읽어 카드 권한(대표님이 연 탭 — 확인 창을 띄울 수 있음)이
// 없으면 물음을 막음으로 바꾸고 결정 요청을 안내한다(judge). 자리는 팀 훅이 처음 본 parent 를 적어 둔 ~/.config/ai-setting/state/parents/<ID> 로 읽고, 그 기록이
// 없을 때만 ~/.paseo/agents/*/<ID>.json 의 labels 를 본다(그 파일의 나머지 — MCP 인증 머리 — 는 읽어 두지도 찍지도 않는다).
// 모듈로 불러 쓸 수 있다(정책 훅이 같은 셸 나누기를 쓴다): import 하면 stdin 을 읽지 않고 decide · simpleCommands · cardRight · seat · judge 를 낸다.
//
// 입력: stdin JSON { tool_name, tool_input, cwd, session_id, permission_mode, agent_id? }
// 출력: 막거나 물어볼 때 hookSpecificOutput.permissionDecision("deny" | "ask"), 되풀이 검색을 .env 를 빼는 꼴로 다시 쓸 때만 "allow" + updatedInput.
// 통과면 아무것도 쓰지 않는다.
// 시험: project-setting 스킬의 tests/guard.test.mjs (node --test)

import { spawnSync } from 'node:child_process'
import * as nodeFs from 'node:fs'
import { existsSync, lstatSync, readdirSync, readFileSync, realpathSync, statSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

/** fs.globSync(Node 22 부터) — 없는 Node 에서는 글롭을 펼치지 않고 예전처럼 묻는다(이름으로 가져오면 그런 Node 에서 가드가 아예 뜨지 않는다) */
const globSyncFn = typeof nodeFs.globSync === 'function' ? nodeFs.globSync : null

const REASON = {
  env: '비밀값 파일(.env*)은 에이전트가 읽거나 고치지 않습니다 (공통 규칙 3). 변수 이름은 .env.example, 1Password 참조는 .env.op를 보고, 값은 1Password에만 둡니다 (~/.codex/procedures/secrets.md). 평문 .env를 옮기거나 지우는 일은 사용자가 자기 터미널에서 합니다.',
  envEcho: '비밀값 파일(.env*) 이름을 echo · printf로 만들어 다른 명령(파이프 · 명령 치환 · 변수 · xargs)에 넘기면 그 명령이 파일을 읽을 수 있어 막습니다 (공통 규칙 3). 알리는 글이면 echo · printf를 홀로 쓰세요(파이프 · 치환 없이 화면이나 파일로). 변수 이름은 .env.example, 1Password 참조는 .env.op를 봅니다.',
  envOutput: '명령 출력을 .env* 파일로 보내지 않습니다 — 값이 파일에 남습니다 (~/.codex/procedures/secrets.md). 1Password 참조 파일은 Edit로 고칩니다.',
  // v35(12): 참조 파일 고치기는 내용으로 가른다 — audit.sh 의 @op-ref-value 와 같은 꼴(줄마다 이름=op://… · 주석 · 빈 줄)이면 통과
  reference: '1Password 참조 파일(.env.op·.env.prod.op·.env.ci.op)에는 줄마다 이름=op://… 참조 · 주석 · 빈 줄만 둡니다 — 참조가 아닌 줄이 있어 막습니다(실제 값일 수 있음). 값은 1Password 에 넣고 참조로 적습니다 (~/.codex/procedures/secrets.md 5).',
  referenceBash: '1Password 참조 파일(.env.op·.env.prod.op·.env.ci.op)은 Edit · Write 도구로 고칩니다 — 가드가 줄마다 이름=op://… 인지 봅니다. cp · mv · sed -i · rm 처럼 셸로 고치거나 옮기거나 지우지 않습니다 (~/.codex/procedures/secrets.md 5).',
  referenceUnknown: '1Password 참조 파일(.env.op·.env.prod.op·.env.ci.op)을 가드가 판정할 수 없는 명령에 넘깁니다 — 사람이 확인합니다. 읽기는 cat · grep 처럼 바로, 고치기는 Edit · Write 도구로 합니다 (~/.codex/procedures/secrets.md 5).',
  referenceDelete: '1Password 참조 파일을 지우거나 다른 이름으로 옮기는 것은 사람이 결정합니다 — 참조 파일은 쓰는 곳마다 하나라 지우면 그곳에 보낼 값이 없어집니다 (~/.codex/procedures/secrets.md 5).',
  // v35(13): 안전망을 에이전트가 스스로 풀지 못하게(P44 · K7) — .mcp.json 은 운영 MCP 의 read_only, project.md 는 병합 승인 칸을 담는다
  selfFiles: '가드 · 권한 · 운영 설정 파일(.claude/hooks/ · .claude/settings*.json · .codex/hooks.json · .codex/rules/ · .mcp.json · .agents/skills/dev-deploy/project.md)은 에이전트가 스스로 풀지 못하게 사람이 결정합니다 (P44). 가드 사본은 /project-audit(install-guard.sh · audit.sh)가 바꿉니다.',
  // v35(11): 막고 다시 쓰게 하던 왕복 대신 가드가 .env 를 빼는 꼴을 넣어 허락한다(바꾼 명령은 설정의 ask · deny 를 다시 지난다)
  rewrite: '재귀 grep · rg --no-ignore 가 .env 를 읽지 않게 빼는 꼴(--exclude=\'.[eE][nN][vV]*\' · --iglob \'!.env*\')을 넣어 실행합니다 (공통 규칙 3).',
  opReveal: '1Password 값을 화면에 내는 명령입니다. 다른 명령에 파이프로 넘기거나(op read … | gh secret set … — ~/.codex/procedures/secrets-setup.md 2), 실행은 scripts/op-run.sh로 합니다 (~/.codex/procedures/secrets.md 6 · 7).',
  opToFile: '1Password 값을 파일로 저장하지 않습니다 (~/.codex/procedures/secrets.md 7 — 하지 않는 것).',
  opArgValue: '비밀 칸의 값을 명령 인자로 넘기지 않습니다 — 같은 Mac의 다른 프로세스가 봅니다. 항목 JSON을 파이프로 넘겨 넣습니다 (~/.codex/procedures/secrets-setup.md 1).',
  keychain: '키체인의 비밀값(서비스 계정 토큰 등)을 명령으로 꺼내지 않습니다. 비밀값이 필요한 실행은 scripts/op-run.sh가 안에서 꺼냅니다 (~/.codex/procedures/secrets.md 6).',
  grep: '재귀 grep은 .gitignore를 무시해 .env 파일까지 읽습니다. .gitignore를 지키는 rg·git grep을 쓰거나, .env를 빼거나, .env와 맞지 않는 --include(예: --include="*.ts")로 좁히세요 (공통 규칙 3). 빼는 패턴은 대소문자를 가리므로 다 덮게 씁니다(소문자 --exclude=".env*"는 .ENV.local을 빼지 못해 막힘): --exclude=\'.[eE][nN][vV]*\'',
  rg: 'rg --no-ignore·-uu는 .env 파일까지 읽습니다. .env를 빼고 실행하세요 (공통 규칙 3). 빼는 패턴은 대소문자를 다 덮게 씁니다(소문자 -g "!.env*"는 .ENV.local을 빼지 못해 막힘): --iglob \'!.env*\' 또는 -g \'!.[eE][nN][vV]*\'',
  privateRaw: '_core/raw/·_private/raw/의 원본은 고치거나 지우거나 옮기지 않고 새 파일만 더합니다 (공통 규칙 8). 꼭 바꿔야 하면 사용자 확인이 필요합니다.',
  privateBulk: '프로젝트 문서(_core·_private)를 폴더째 지우거나 밖으로 옮기기, 재귀 삭제, 파이프로 받은 목록을 한꺼번에 지우거나 고치기는 되돌리기 어렵습니다 (공통 규칙 8). 사용자 확인이 필요합니다.',
  privateOut: '프로젝트 문서(_core·_private)를 git에 넣거나, 다른 곳으로 보내거나, 판정할 수 없는 명령에 넘깁니다 (공통 규칙 8: 커밋하지 않음). 사용자 확인이 필요합니다.',
  privateScript: '프로젝트 문서(_core·_private)는 스크립트(python·node 등)로 고치거나 지우지 않습니다 (공통 규칙 8: Edit·Write 도구로만 고치고, 진행·게이트·문제·맥락 항목은 core.sh·stage.sh로). 가드는 스크립트가 무엇을 바꾸는지 판정할 수 없어 막았습니다. 고칠 곳마다 Edit 도구를 쓰거나 파일 전체를 Write 도구로 다시 쓰고, 지우거나 옮길 때는 rm·mv 같은 명령을 쓰세요(가드가 판정합니다). 읽기만 하는 분석이면 파일에 쓰는 코드 없이 결과를 화면에 내도록 다시 쓰세요.',
  dbReset: '연결된 원격 DB 초기화(--linked·--db-url)는 막혀 있습니다. 로컬은 `supabase db reset`만 씁니다.',
  hookBypass: '커밋 전 검사(.githooks/pre-commit의 비밀값 검사)를 건너뛰거나 끄는 명령(--no-verify, core.hooksPath 지우기 · core 절 지우기 · 이름 바꾸기, -c · --config-env · GIT_CONFIG_PARAMETERS · GIT_CONFIG_KEY_n으로 덮어쓰기)은 막혀 있습니다 (공통 규칙 3).',
  hooksPath: '커밋 전 검사가 도는 곳(core.hooksPath)을 .githooks 밖으로 바꾸거나, 범위가 넓은 설정(--global · --system)이나 다른 설정 파일(--file · -f · --blob)에 적으면 커밋 전 비밀값 검사(.githooks/pre-commit)가 돌지 않거나 다른 저장소의 훅까지 바뀌어 막혀 있습니다 (공통 규칙 3). 훅 경로는 이 저장소에 `git config core.hooksPath .githooks`로만 둡니다. 다른 훅을 써야 하면 사용자가 자기 터미널에서 바꿉니다.',
  privateEdit: '프로젝트 문서(_core·_private)의 있는 문서는 Edit·Write 도구로 고칩니다 (공통 규칙 8: 스크립트로 고치지 않음). sed -i·>>·tee 대신 Edit 도구를 쓰세요. 새 파일을 만드는 것과 raw/에 원본을 더하는 것은 그대로 됩니다.',
  progress: '진행 파일(_core의 log.tsv·state.md·index.md, 아이디어 폴더의 log.tsv, 아이디어 장부 _ideas/ledger.csv)은 스크립트만 씁니다 (공통 규칙 8). 진행·게이트·문제·맥락은 그 명령으로 남기고(예: core.sh note, core.sh problem add, stage.sh gate, 아이디어 폴더는 stage.sh set 2 --idea), state.md는 core.sh state가, 파일 목록 index.md는 core.sh index가 다시 만들고, 장부는 ledger.sh(decide · review)만 고칩니다.',
  local: '프로젝트 가드 확장(.claude/hooks/guard.local.mjs)이 판정하지 못해 이 프로젝트의 전용 규칙을 확인할 수 없습니다. 사용자 확인이 필요합니다 — 확장 파일을 고치세요.',
  push: '사람이 승인하는 push입니다 — 기본 가지(main·master, 원격이 알려 준 기본 가지)로 가는 push(받는 쪽이 기본 가지인 refspec — HEAD:main · x:main — 포함), 보낼 가지를 풀 수 없는 push(분리된 HEAD · push.default=matching · remote.<원격>.push 설정 · upstream 이 없어 @{push} 를 풀지 못함), 가지나 원격을 변수 · 명령 치환으로 준 push("$B"·$(git branch --show-current) — 훅은 그 값을 모릅니다), 로컬 사본이 없는 원격 가지 · 태그 지우기(--delete·-d·:가지), 한꺼번에 보내기(--all·--branches·--mirror·--prune·--tags·--follow-tags·refs/tags/·와일드카드), 설정을 덮어쓴 push(-c · --config-env · GIT_CONFIG_* — credential.helper 만 예외) (공통 규칙 0). 작업 가지는 `git push -u origin <가지 이름>`처럼 가지 이름을 글자로 적거나, 그 가지에서 이름 없이 보내면 묻지 않습니다.',
  // v35(2026-10-18 R-265): 강제 push 는 묻지 않고 막는다 — 작업 가지는 --force-with-lease 가 같은 일을 남의 커밋을 지키며 한다(「한 번에 승인」 B-2)
  pushForce: '강제 push(-f·--force·+가지)는 막습니다 — 원격의 남의 커밋을 덮을 수 있습니다. 작업 가지면 `git push --force-with-lease origin <가지 이름>`으로 다시 보냅니다(원격이 마지막으로 본 그대로일 때만 덮음). 기본 가지(main·master·원격이 알려 준 기본 가지)는 --force-with-lease 로도 강제로 보내지 않습니다 (공통 규칙 0).',
  pushDeleteDefault: '기본 가지(main·master·원격이 알려 준 기본 가지)를 원격에서 지우는 push는 막습니다 (공통 규칙 0).',
  branchDrop: '끝 커밋이 어떤 원격 가지에도 없는 가지를 git branch -D 로 지웁니다 — 그 커밋은 reflog 가 지워지면(30일 뒤) 되찾을 수 없습니다. 작업 가지면 먼저 push 한 뒤 지우거나 사람이 결정합니다. 병합된 가지는 git branch -d 로 지웁니다.',
  mainCommit: '기본 가지(main·master)에 바로 커밋하지 않습니다 — 카드 권한이 없는 세션(팀원 · 서브에이전트 · 다른 세션이 연 세션)은 작업 가지에서만 커밋합니다. `git switch -c <작업 가지>`로 가지를 만든 뒤 커밋하세요(고친 파일은 그대로 따라갑니다).',
  cleanIgnored: '무시된 파일까지 지우는 명령(git clean -x · -X, git stash -a · --all)은 막습니다 — .gitignore 에 든 _core(프로젝트 문서)와 .env(비밀값)까지 지웁니다 (공통 규칙 3 · 8). 추적하지 않는 파일만 지우려면 git clean -fd(-x 없이), 잠깐 치우려면 git stash -u 를 씁니다.',
  checkRecord: '검사 통과 기록(git 폴더의 check-once-passed)은 그 프로젝트의 검사 명령만 씁니다 — 손으로 쓰면 같은 내용이 통과했다고 속여 커밋 전 검사(타입 · 시험)를 건너뜁니다. CI 가 없는 프로젝트는 그 검사가 전부입니다. 기록을 새로 만들려면 그 프로젝트의 검사 명령을 다시 돌립니다(틀은 `node .githooks/check-once.mjs --force`, 프로젝트가 자기 명령을 두었으면 그것 — 예: `pnpm check --force`).',
  checkRecordBash: 'Bash 에서는 검사 통과 기록(check-once-passed)의 이름을 언급만 해도(읽기 · 조회 포함) 막습니다 — 읽기는 Read 도구로 합니다. 기록은 그 프로젝트의 검사 명령만 씁니다(손으로 쓰면 커밋 전 검사를 건너뜀). 새로 만들려면 그 검사 명령을 다시 돌립니다(틀은 `node .githooks/check-once.mjs --force`, 프로젝트가 자기 명령을 두었으면 그것 — 예: `pnpm check --force`).',
  internal: '가드 훅이 입력을 판정하지 못했습니다. .env·_core·_private가 걸린 호출이라 안전을 위해 막습니다.',
  // 따옴표 없는 heredoc(<<EOF) 본문의 명령 치환 때문에 막을 때 그 까닭 뒤에 붙인다 — 글로만 쓰려던 본문이 실행되는 줄 모르고 막히던 것 (2026-10-17 R-250)
  heredocQuote: ' 본문을 글로만 쓰려면 구분자에 따옴표를 쳐 <<\'EOF\' 로 씁니다(따옴표 없는 <<EOF 는 셸이 본문의 `…` · $( ) 를 실제로 실행합니다).',
}

/**
 * .env 계열 파일 이름 — `.env`, `.env.local`, `.env.example`, `.env.op` …
 * 공백이 든 이름은 파일이 아니라 글로 본다(`gh issue create --title ".env.local 정리"`). 글자 속 `.env`는 refsSecretEnv가 따로 본다
 * 대소문자는 가리지 않는다 — macOS 기본 APFS 에서는 `.ENV.local` · `.Env` 가 `.env.local` · `.env` 를 연다(2026-10-17 R-226). 참조 파일 · 이름 목록 · 글롭 · 글자 속 이름도 같다
 */
function isEnvFileName(name) {
  return /^\.env(\.\S+)?$/i.test(name)
}

/**
 * 1Password 참조 파일 이름 — `.env.op`(로컬), `.env.prod.op`(운영), `.env.ci.op`(CI) 같은 `.env[.이름].op`.
 * 값이 아니라 `이름=op://…`만 담아 커밋한다(~/.codex/procedures/secrets.md 5: 쓰는 곳마다 하나). 하위 앱 폴더에 있어도 참조 파일이다.
 * 읽기는 자유, 고칠 때는 사람이 내용을 보고 승인한다. 실제 값이 섞였는지는 project-setting의 audit.sh가 내용으로 본다.
 */
const REFERENCE_NAME = /^\.env(\.[\w-]+)?\.op$/i

/** ctx: { cwd — 상대 경로를 푸는 곳, root — 프로젝트 루트 }. 프로젝트 밖의 파일은 참조 파일로 보지 않는다 */
function isReferenceFile(filePath, ctx) {
  if (!REFERENCE_NAME.test(path.posix.basename(filePath))) return false
  const rel = path.relative(path.resolve(ctx.root), path.resolve(ctx.cwd, filePath))
  return rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel)
}

/** 비밀값 파일 — `.env*` 중 이름 목록 `.env.example`과 프로젝트 안의 참조 파일만 빼고 전부 */
function isSecretEnvPath(filePath, ctx) {
  const name = path.posix.basename(filePath)
  return isEnvFileName(name) && name.toLowerCase() !== '.env.example' && !isReferenceFile(filePath, ctx)
}

/**
 * 마지막 경로 조각이 글롭이고 .env 파일을 집어낼 수 있는가 — `.*`, `.env*`, `.e?v.local`.
 * 셸 글롭은 점으로 시작하는 이름을 명시적인 점 없이는 집지 않으므로(`*`는 .env.local을 못 집는다)
 * 점으로 시작하는 조각만 본다. 글롭으로 해석할 수 없는 조각(짝 없는 `[` 등)은 글자 그대로라 무해하다.
 * 셸은 따옴표 밖의 * ? [ 만 펼친다. 그래서 Bash 명령에서는 그런 글자가 있던 단어(splitCommands의 globs)와
 * 프로그램이 스스로 푸는 패턴(selfGlobPatterns)에만 쓴다 — sed 's/.*=//'의 `.*`는 글자 그대로다 (2026-10-03 content-studio)
 */
function globMayMatchSecretEnv(word) {
  const last = word.split('/').pop() ?? ''
  if (!last.startsWith('.') || !/[*?[]/.test(last)) return false
  try {
    const re = new RegExp(
      `^${last.replace(/[.+^${}()|\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')}$`,
      'i',
    )
    return ['.env', '.env.local', '.env.production'].some((name) => re.test(name))
  } catch {
    return false
  }
}

/**
 * 단어가 비밀값 파일을 가리키는가. substring이면 코드 문자열 안의 참조(readFileSync('.env.local'))도 본다.
 * glob은 단어에 따옴표 밖의 * ? [ 가 있었는가다 — 그때만 셸이 펼치므로 글롭으로 본다 (cat .env*, cat ".env"*)
 */
function refsSecretEnv(word, substring, ctx, glob = false) {
  for (const raw of word.split(/[=,:]/)) {
    // `@파일`은 그 파일 내용을 읽어 보내는 문법이다 (gh api -F key=@파일, curl -d @파일)
    const part = raw.replace(/^@/, '')
    if (part === '') continue
    if (isSecretEnvPath(part, ctx) || (glob && globMayMatchSecretEnv(part))) return true
  }
  if (!substring) return false
  // 셸 · 인터프리터가 다시 읽는 글(bash -c '…' · heredoc 본문 · node -e '…')은 줄 이음(\ + 줄바꿈)을 지운 글로도 본다 — `bash -c 'cat .e\⏎nv.local'` (2026-10-13 총괄)
  for (const text of word.includes('\\\n') ? [word, word.replace(/\\\n/g, '')] : [word]) {
    for (const match of text.matchAll(/(^|[^\w.-])(\.env(?:\.[\w.-]+)?)(?![\w-])/gi)) {
      if (isSecretEnvPath(match[2], ctx)) return true
    }
  }
  return false
}

/** 단어가 프로젝트 안의 1Password 참조 파일을 가리키는가 */
function refsReferenceFile(word, ctx) {
  return word.split(/[=,:]/).some((part) => part !== '' && isReferenceFile(part, ctx))
}

/** 단어가 .env 계열 파일(값·이름·참조 무엇이든)을 가리키는가 — 출력을 보내는 곳 판정용 */
function refsAnyEnvFile(word) {
  return word
    .split(/[=,:]/)
    .some((part) => part !== '' && (isEnvFileName(path.posix.basename(part)) || globMayMatchSecretEnv(part)))
}

/**
 * 경로 어딘가에 `_private` 폴더가 있는가. 프로젝트 기준 상대 경로로 보지 않는다 — 워크트리에서
 * 본 저장소의 `_private/`를 절대 경로로 가리켜도(AGENTS.md가 그렇게 쓰라고 한다) 걸려야 한다.
 * 다른 프로젝트의 `_private/`도 같은 규칙(공통 규칙 8)이다.
 * 회사 프로젝트의 `_private`는 공유 드라이브 Projects/<이름>으로 가는 링크라, 링크를 거치지 않고 드라이브 경로로
 * 가리켜도 `_private`로 본다(PRIVATE_DRIVE, 2026-10-04).
 */
function isUnderPrivate(filePath, projectDir) {
  const resolved = path.resolve(projectDir, filePath)
  const parts = resolved.split(path.sep)
  return parts.includes('_private') || coreIndex(parts) >= 0 || PRIVATE_DRIVE.test(resolved)
}

/**
 * 프로젝트 문서 `_core/`(2026-10-12 To-Be 구조, 공통 규칙 8) — Git 체크아웃 뿌리(`.git` 폴더나 워크트리의 `.git` 파일이 있는 곳)
 * 바로 아래의 `_core`만 본다. 코드 폴더(`src/pkg/_core`, `site-packages/numpy/_core`)와 `pydantic_core` 같은 이름은 아니다.
 * 워크트리에서는 메인 체크아웃의 `_core`를 절대 경로로 가리키므로 그것도 걸린다. 옮기는 동안은 `_private`도 그대로 본다.
 * 경로 조각의 차례(없으면 -1)
 */
function coreIndex(parts) {
  for (let i = parts.length - 1; i > 0; i--) {
    if (parts[i] === '_core' && existsSync(`${parts.slice(0, i).join(path.sep)}${path.sep}.git`)) return i
  }
  return -1
}

/**
 * 글(셸 단어, -c 코드, heredoc 본문) 속 경로 가운데 체크아웃 뿌리의 `_core`를 가리키는 것이 있는가 — base 기준으로 푼다.
 * `_core` 앞이 `/`이거나 글 조각의 맨 앞일 때만 본다(`pydantic_core`, `numpy._core`는 아님)
 */
function mentionsCoreIn(text, base) {
  if (typeof text !== 'string' || !text.includes('_core')) return false
  for (const m of text.matchAll(/[\w.~${}\/-]*_core(?:\/[\w.\/-]*)?/g)) {
    const token = m[0]
    const at = token.indexOf('_core')
    if (at > 0 && token[at - 1] !== '/') continue
    if (privateSpot(path.resolve(base, expandHome(token))) !== null) return true
  }
  return false
}

/** 셸 단어나 글이 프로젝트 문서(_core·_private, 드라이브 원본)를 가리키는가 */
function mentionsPrivate(text, base) {
  return mentionsPrivatePath(text) || mentionsCoreIn(text, base)
}

/**
 * 프로젝트 문서에 쓰는 것이 일인 스크립트 — 진행·게이트·문제·맥락은 이 둘만 바꾼다(공통 규칙 8, 2026-10-12).
 * 인자의 판정은 그 스크립트의 시험이 맡으므로 프로젝트 문서 판정(3번)에서 인자를 보지 않는다. 출력 리디렉션(>)과 비밀값 판정은 그대로 돈다.
 * 홈의 스킬 폴더(~/.agents/skills와 Claude가 보는 링크 ~/.claude/skills)에 있는 것만 — 프로젝트 안의 같은 이름 파일은 아니다
 */
const TRUSTED_WRITERS = ['project-setting/scripts/core.sh', 'product-stage/scripts/stage.sh', 'idea-review/scripts/ledger.sh']
/** 믿는 스크립트를 돌리는 셸 — SHELLS를 넓혀도(2026-10-13) 여기는 그대로 둔다(dash · csh 로 돌리는 core.sh 를 새로 믿지 않는다) */
const TRUSTED_WRITER_SHELLS = new Set(['bash', 'sh', 'zsh'])
function isTrustedWriter(name, args, program, base) {
  const script = TRUSTED_WRITER_SHELLS.has(name) ? (args.find((a) => !a.startsWith('-')) ?? '') : program
  if (!HOME || script === '') return false
  const resolved = path.resolve(base, expandHome(script))
  return ['.agents/skills', '.claude/skills'].some((dir) => TRUSTED_WRITERS.some((w) => resolved === path.join(HOME, dir, w)))
}

/** 회사 공유 드라이브 Projects 안 — Google Drive 앱이 여는 경로. 셸 단어에는 ~·$HOME이 앞에 올 수 있어 앞부분은 보지 않는다 */
const PRIVATE_DRIVE = /\/Library\/CloudStorage\/GoogleDrive-[^/]+\/(Shared drives|공유 드라이브)\/Projects(\/|$)/

/**
 * 공유 드라이브 Projects의 상위 — CloudStorage, 계정 폴더(GoogleDrive-<계정>), 공유 드라이브 목록(Shared drives).
 * 경로가 여기서 끝나거나 뒤에 글롭만 붙으면(rm -rf …/Shared drives/*) 그 아래 Projects까지 닿는다.
 * 형제 공유 드라이브(…/Shared drives/<다른 이름>/…)와 내 드라이브(…/My Drive/…)는 기획 자료가 아니다 (2026-10-04)
 */
const PRIVATE_DRIVE_PARENT = /\/Library\/CloudStorage(\/GoogleDrive-[^/]+(\/(Shared drives|공유 드라이브))?)?\/?[*?]*$/

/** 셸 단어가 기획 자료(_private, 그 드라이브 원본, 원본을 품은 상위 폴더)를 가리키는가 */
function mentionsPrivatePath(word) {
  return word.includes('_private') || PRIVATE_DRIVE.test(word) || PRIVATE_DRIVE_PARENT.test(word)
}

const HOME = process.env.HOME ?? ''

/** 셸이 펼칠 홈 표기(~, $HOME, ${HOME})를 실제 홈으로 — cd 대상을 따라갈 때만 쓴다 */
function expandHome(word) {
  return HOME ? word.replace(/^(~|\$HOME|\$\{HOME\})(?=\/|$)/, HOME) : word
}

/** 작업 폴더가 기획 자료 안이거나 그 상위(드라이브 계정·공유 드라이브 목록)인가 — 그 안의 상대 경로 쓰기도 기획 자료다 */
function isPrivateDir(dir, ctx) {
  return typeof dir === 'string' && dir !== '' && (isUnderPrivate(dir, ctx.root) || PRIVATE_DRIVE_PARENT.test(dir))
}

/**
 * 기획 자료 안의 자리 — 기획 자료 뿌리(`_private` 폴더, 드라이브의 `Projects/<이름>`)에서 본 상대 경로.
 * null이면 기획 자료가 아니고, ''은 뿌리 자체, 'parent'는 뿌리를 품은 상위(드라이브 `Projects` 자체와 그 위), 'raw/…'는 원본이다.
 * 아이디어 폴더(`Projects/_ideas/<이름>/`)는 그 폴더를 뿌리로 본다. `_ideas` 자체와 그 바로 아래(아이디어 폴더, 장부 파일)는
 * 뿌리라서 지우거나 옮길 때 묻는다 (2026-10-07, 같은 날 jarvis 검토로 아이디어 폴더 자체를 뿌리로 고침)
 */
function privateSpot(resolved) {
  const parts = resolved.split(path.sep)
  const i = Math.max(parts.lastIndexOf('_private'), coreIndex(parts))
  if (i >= 0) return parts.slice(i + 1).filter(Boolean).join('/')
  const m = resolved.match(PRIVATE_DRIVE)
  if (m) {
    const rest = resolved.slice((m.index ?? 0) + m[0].length).split('/').filter(Boolean)
    if (rest.length === 0) return 'parent'
    if (rest[0] === '_ideas' && rest.length >= 2) return rest.slice(2).join('/')
    return rest.slice(1).join('/')
  }
  return PRIVATE_DRIVE_PARENT.test(resolved) ? 'parent' : null
}

const isRawSpot = (spot) => spot === 'raw' || spot.startsWith('raw/')

/**
 * 스크립트만 쓰는 진행 파일인가 (2026-10-12 To-Be): 뿌리 `_core`의 log.tsv · state.md · index.md, 아이디어 폴더(`_ideas/<이름>`)의 log.tsv.
 * core.sh · stage.sh(isTrustedWriter)만 고친다. 옮기기 전 `_private/index.md`는 사람이 고치는 목록이라 넣지 않는다
 */
function isProgressFile(resolved) {
  const parts = resolved.split(path.sep)
  const ci = coreIndex(parts)
  if (ci >= 0 && ['log.tsv', 'state.md', 'index.md'].includes(parts.slice(ci + 1).filter(Boolean).join('/'))) return true
  const m = resolved.match(PRIVATE_DRIVE)
  if (!m) return false
  const rest = resolved.slice((m.index ?? 0) + m[0].length).split('/').filter(Boolean)
  // 아이디어 장부(_ideas/ledger.csv)도 ledger.sh 만 고친다(아이디어 탭의 가드, 리허설 2차 3 · D4 2026-10-12)
  return (rest.length === 3 && rest[0] === '_ideas' && rest[2] === 'log.tsv') || (rest.length === 2 && rest[0] === '_ideas' && rest[1] === 'ledger.csv')
}

/** 있는 파일인가(폴더가 아님) — 셸로 덮어쓰거나 덧붙이면 그 문서를 고치는 셈이다 */
function isExistingFile(resolved) {
  try {
    return lstatSync(resolved, { throwIfNoEntry: false })?.isFile() === true
  } catch {
    return false
  }
}
const isTopSpot = (spot) => spot === '' || spot === 'parent'

/** 둘이 같은 기획 자료 안인가 — 뿌리(자리를 뗀 앞부분)가 같은가. 뿌리의 위와 판정할 수 없는 곳은 아니다 */
function sameRoot(a, b) {
  const inside = (t) => t.spot !== null && t.spot !== '?' && t.spot !== 'parent' && !t.unknown
  const rootOf = (t) => (t.spot === '' ? t.resolved : t.resolved.slice(0, t.resolved.length - t.spot.length - 1))
  return inside(a) && inside(b) && rootOf(a) === rootOf(b)
}

/** 기획 자료를 고치는 명령 가운데 판정할 수 있는 로컬 파일 명령 — 나머지는 밖으로 보낼 수 있어 사용자 확인 */
const PRIVATE_REMOVERS = new Set(['rm', 'rmdir', 'unlink', 'trash', 'shred', 'srm'])
const PRIVATE_COPIERS = new Set(['cp', 'mv', 'ln', 'ditto'])
const PRIVATE_TOUCHERS = new Set(['touch', 'tee', 'truncate'])
/** curl·wget이 받은 것을 쓰는 곳 — 값을 받는 옵션 (curl -O는 값을 받지 않는다) */
const DOWNLOAD_OUTPUT_OPTIONS = {
  curl: new Set(['-o', '--output', '--output-dir']),
  wget: new Set(['-O', '--output-document', '-P', '--directory-prefix']),
}
/** curl · wget의 j번째 인자가 받은 것을 쓰는 곳(-o 값, --output=…)인가 */
function isDownloadOutput(name, args, j) {
  const options = DOWNLOAD_OUTPUT_OPTIONS[name]
  return options.has(args[j - 1] ?? '') || [...options].some((o) => o.startsWith('--') && (args[j] ?? '').startsWith(`${o}=`))
}

/**
 * 이 명령이 고른 인자(picked, 판정된 대상)의 파일에 쓰거나 그것을 지우는가 — sed -i, tee · truncate · touch, 지우기,
 * 복사 · 링크의 받는 곳(마지막 위치 인자)과 mv의 양쪽, curl · wget이 받아 쓰는 곳. 진행 파일 판정에 쓴다
 */
function writesTarget(name, args, picked) {
  if (picked.length === 0) return false
  if (name === 'sed') return !readsOnly(name, args)
  if (PRIVATE_TOUCHERS.has(name) || PRIVATE_REMOVERS.has(name) || name === 'mv') return true
  if (PRIVATE_COPIERS.has(name)) {
    const positional = args.map((w, j) => ({ w, j })).filter(({ w }) => !w.startsWith('-'))
    const destJ = positional.length >= 2 ? positional[positional.length - 1].j : -1
    return picked.some((t) => t.j === destJ)
  }
  if (Object.hasOwn(DOWNLOAD_OUTPUT_OPTIONS, name)) return picked.some((t) => isDownloadOutput(name, args, t.j))
  return false
}

/** raw/ 겹침을 볼 때 세는 이름의 한도 — 넘으면 모른다고 보고 묻는다(훅 시간 제한 10초 안에 끝나게) */
const COPY_SCAN_LIMIT = 2000
const isInsideDir = (inner, outer) => inner === outer || inner.startsWith(`${outer}${path.sep}`)
/**
 * 폴더 src 를 폴더 dest 에 합치면 dest 의 있는 이름을 덮어쓰는가 — 폴더끼리는 안으로 들어가 보고, 파일(링크 포함)이 같은 자리에 있으면 덮어쓴다.
 * dest 가 없으면 새로 만든다(덮어쓰지 않음). 이름이 너무 많거나 읽지 못하면 덮어쓴다고 본다
 */
function treeOverlaps(src, dest) {
  let seen = 0
  const walk = (from, to) => {
    const there = lstatSync(to, { throwIfNoEntry: false })
    if (!there) return false
    if (!there.isDirectory()) return true
    let entries
    try {
      entries = readdirSync(from, { withFileTypes: true })
    } catch {
      return true
    }
    for (const entry of entries) {
      if (++seen > COPY_SCAN_LIMIT) return true
      const next = path.join(to, entry.name)
      if (entry.isDirectory()) {
        if (walk(path.join(from, entry.name), next)) return true
      } else if (lstatSync(next, { throwIfNoEntry: false })) return true
    }
    return false
  }
  try {
    return walk(src, dest)
  } catch {
    return true
  }
}
/**
 * 10. 폴더 destDir 로 보내는 복사 · 옮기기의 보내는 낱말 하나가 받는 곳의 있는 이름을 덮어쓸 수 있는가 (v35, 2026-10-18 — raw/ 에 새 파일을 더하는 것은 기본 규칙 8 이 허용).
 * 글롭(isGlob — 따옴표 밖의 * ? [)은 셸처럼 펼쳐(fs.globSync) 하나씩 본다. ditto 와 끝이 / · /. 인 cp -R 은 보내는 폴더의 내용을 받는 폴더에, 그 밖의 cp -R 은
 * 받는 폴더 안의 같은 이름 폴더에 합치므로 겹치는 이름이 있는지 본다(treeOverlaps). 받는 곳이 보내는 폴더 안이면 덮어쓴다고 본다.
 * 모르면(변수 · 명령 치환 · 중괄호 펼치기 · 지금 폴더 '.' · 글롭을 펼칠 수 없음 · 너무 많음) 덮어쓴다고 본다(묻는다). ** 는 펼치지 않는다 — 셸(globstar 꺼짐)과 뜻이 다르고
 * fs.globSync 가 홈 전체를 훑으면 훅 시간 제한(10초)을 넘겨 판정 없이 지나간다
 */
function copyOverlaps(name, tree, word, isGlob, destDir, base) {
  if (word === '' || word === '.' || /[$`{}]/.test(word) || (isGlob && word.includes('**'))) return true
  const expanded = expandHome(word)
  let sources = [path.resolve(base, expanded)]
  if (isGlob) {
    if (globSyncFn === null) return true
    try {
      sources = globSyncFn(path.resolve(base, expanded)).map((found) => path.resolve(base, found))
    } catch {
      return true
    }
    if (sources.length > COPY_SCAN_LIMIT) return true
  }
  const contents = !isGlob && /\/\.?$/.test(word)
  for (const src of sources) {
    const isDir = lstatSync(src, { throwIfNoEntry: false })?.isDirectory() === true
    if (isDir && (name === 'ditto' || (tree && contents))) {
      if (isInsideDir(destDir, src) || treeOverlaps(src, destDir)) return true
    } else if (isDir && tree) {
      const into = path.join(destDir, path.basename(src))
      if (isInsideDir(destDir, src) || treeOverlaps(src, into)) return true
    } else if (lstatSync(path.join(destDir, path.basename(src)), { throwIfNoEntry: false })) return true
  }
  return false
}

/**
 * 3. 기획 자료(_private) — 읽기·쓰기는 자유다(공통 규칙 8, 2026-10-07 사용자 결정). 사용자 확인을 받는 것은 셋이다:
 *    raw/의 원본을 고치거나 지우거나 옮기기, 폴더째(뿌리·그 위) 지우거나 옮기기와 재귀 삭제,
 *    기획 자료를 git에 넣거나 밖으로 보내거나 판정할 수 없는 명령에 넘기기.
 *    -r 없이 폴더를 지우는 명령(trash), 폴더를 기획 자료 밖으로 옮기기, 받는 폴더 안을 합치는 폴더째 복사(ditto, cp -R)도
 *    같이 본다 (2026-10-07 jarvis 검토).
 * targets: 기획 자료를 가리키는 인자 { word, j, spot, resolved, unknown, glob }, outputs: 출력 리디렉션 대상(과 sort -o 의 파일)
 * readOnly: 읽기만 하는 perl · awk 한 줄 프로그램(perlReadsOnly · awkReadsOnly)이나 파일을 건드리지 않는 셸 내장 명령(NO_FILE_BUILTINS) — cat 처럼 본다 (2026-10-15 R-168)
 * argGlobs: args 와 같은 차례로 그 낱말에 따옴표 밖의 * ? [ 가 있었는가, base: 상대 경로를 푸는 곳 — raw/ 로 보내는 복사의 겹침을 볼 때 쓴다(v35 10)
 */
function judgePrivate(name, args, targets, outputs, dirSpot, gitEnv = false, readOnly = false, argGlobs = [], base = '.') {
  const mayExist = (t) => t.unknown || t.glob || existsSync(t.resolved)
  // 실제 폴더인가 — 링크는 링크만 지우거나 옮기므로 폴더로 보지 않는다. 글롭·변수는 알 수 없어 따로 본다
  const isFolder = (t) => {
    if (t.unknown || t.glob) return false
    try {
      return lstatSync(t.resolved, { throwIfNoEntry: false })?.isDirectory() === true
    } catch {
      return false
    }
  }
  // 진행 파일은 core.sh · stage.sh만 쓴다(그 둘의 인자는 이 판정에 오지 않는다). 쓰는 명령만 막고, 읽기 · 복사해 가기는 그대로,
  // git add 같은 나머지는 아래 판정(사용자 확인)대로 둔다
  const progress = (t) => !t.unknown && !t.glob && isProgressFile(t.resolved)
  if (outputs.some(progress)) return { decision: 'deny', reason: REASON.progress }
  if (writesTarget(name, args, targets.filter(progress))) return { decision: 'deny', reason: REASON.progress }
  for (const t of outputs) {
    if (t.spot === '?') return { decision: 'ask', reason: REASON.privateOut }
    if (isRawSpot(t.spot) && mayExist(t)) return { decision: 'ask', reason: REASON.privateRaw }
    // 있는 문서를 >·>>로 덮어쓰거나 덧붙이면 셸로 고치는 것이다(공통 규칙 8, 2026-10-12 리허설). 새 파일은 그대로
    if (!isTopSpot(t.spot) && !t.unknown && !t.glob && isExistingFile(t.resolved)) return { decision: 'deny', reason: REASON.privateEdit }
  }
  // 반복문 · 조건문의 끝(done · fi), 변수 이름만 받는 read는 파일을 건드리지 않는다
  // (2026-10-12 리허설 2차 24: `cd _core/raw; for f in …; do grep …; done`의 done을 원본 고치기로 봄)
  if (SHELL_SYNTAX.has(name)) return null
  if (targets.length === 0) {
    // raw/ 안으로 들어가 판정할 수 없는 명령을 돌리면 원본을 바꿀 수 있다
    if (dirSpot !== null && isRawSpot(dirSpot) && !READ_ONLY.has(name) && !readOnly && name !== 'mkdir' && !PRIVATE_TOUCHERS.has(name)) {
      return { decision: 'ask', reason: REASON.privateRaw }
    }
    return null
  }
  if (targets.some((t) => t.spot === '?')) return { decision: 'ask', reason: REASON.privateOut }
  const recursive = args.some((a) => /^-[A-Za-z]*[rR][A-Za-z]*$/.test(a) || a === '--recursive')

  if (name === 'find') {
    const mutating = args.some((a) => /^-(delete|exec|execdir|ok|okdir|fprint)/.test(a))
    return mutating ? { decision: 'ask', reason: REASON.privateBulk } : null
  }
  if (name === 'sed') {
    const inPlace = args.some((a) => /^-[A-Za-z]*i/.test(a) || a.startsWith('--in-place'))
    if (!inPlace) return null
    if (targets.some((t) => isRawSpot(t.spot))) return { decision: 'ask', reason: REASON.privateRaw }
    // raw/ 밖의 문서를 sed -i로 고치는 것도 스크립트 편집이다(공통 규칙 8, 2026-10-12 리허설에서 통과하던 것)
    return targets.some((t) => !isTopSpot(t.spot)) ? { decision: 'deny', reason: REASON.privateEdit } : null
  }
  // 읽기만 하는 명령 — sort -o 의 쓰는 곳은 위의 outputs 로 따로 보았다. bat --pager 는 다른 프로그램을 돌린다(아래 판정할 수 없는 명령)
  if ((READ_ONLY.has(name) && (name !== 'bat' || readsOnly(name, args))) || name === 'mkdir' || readOnly) return null
  if (PRIVATE_REMOVERS.has(name)) {
    if (targets.some((t) => isTopSpot(t.spot)) || recursive || targets.some((t) => t.glob && !t.spot.includes('/'))) {
      return { decision: 'ask', reason: REASON.privateBulk }
    }
    // 폴더는 -r 없이도 통째로 지워진다(trash). rmdir는 빈 폴더만 지운다. trash는 글롭·변수로 폴더를 집을 수 있다
    if (name !== 'rmdir' && targets.some((t) => isFolder(t) || (name === 'trash' && (t.glob || t.unknown)))) {
      return { decision: 'ask', reason: REASON.privateBulk }
    }
    return targets.some((t) => isRawSpot(t.spot)) ? { decision: 'ask', reason: REASON.privateRaw } : null
  }
  if (PRIVATE_TOUCHERS.has(name)) {
    if (targets.some((t) => isRawSpot(t.spot) && mayExist(t))) return { decision: 'ask', reason: REASON.privateRaw }
    // tee · truncate로 있는 문서를 고치는 것도 셸 편집이다. touch는 시각만 바꾼다
    if (name !== 'touch' && targets.some((t) => !isTopSpot(t.spot) && !t.unknown && !t.glob && isExistingFile(t.resolved))) {
      return { decision: 'deny', reason: REASON.privateEdit }
    }
    return null
  }
  if (PRIVATE_COPIERS.has(name)) {
    // 마지막 위치 인자가 받는 곳, 나머지는 보내는 곳. mv는 보내는 곳을 지우는 셈이다
    const positional = args.map((w, j) => ({ w, j })).filter(({ w }) => !w.startsWith('-'))
    const destJ = positional.length >= 2 ? positional[positional.length - 1].j : -1
    const sources = targets.filter((t) => t.j !== destJ)
    const dest = targets.find((t) => t.j === destJ)
    if (name === 'mv' && sources.some((t) => isTopSpot(t.spot))) return { decision: 'ask', reason: REASON.privateBulk }
    if (name === 'mv' && sources.some((t) => isRawSpot(t.spot))) return { decision: 'ask', reason: REASON.privateRaw }
    // 폴더를 기획 자료 밖(다른 기획 자료 포함)으로 옮기면 폴더째 지우는 셈이다. 같은 기획 자료 안의 이름 바꾸기·정리는 그대로 둔다
    if (name === 'mv' && sources.some((t) => isFolder(t) && !(dest && sameRoot(t, dest)))) {
      return { decision: 'ask', reason: REASON.privateBulk }
    }
    // 폴더째 복사(ditto, cp -R·-a)는 받는 폴더 안을 합친다 — 뿌리로 받아도 raw/의 원본을 덮어쓸 수 있다
    const copiesTree =
      name === 'ditto' ||
      (name === 'cp' && args.some((a) => /^-[A-Za-z]*[rRa][A-Za-z]*$/.test(a) || a === '--recursive' || a === '--archive'))
    if (dest && (isRawSpot(dest.spot) || (copiesTree && isTopSpot(dest.spot))) && mayExist(dest)) {
      let overwrites = true
      if (!dest.unknown && !dest.glob && statSync(dest.resolved).isDirectory()) {
        // 폴더로 보내면 같은 이름의 원본이 있을 때만 덮어쓴다(v35 10, 2026-10-18 — 예전에는 글롭 · 폴더째 복사를 늘 물었다): 글롭은 펼쳐 보고(fs.globSync),
        // ditto 와 끝이 / · /. 인 cp -R 은 보내는 폴더의 내용을, 그 밖의 cp -R 은 받는 폴더 안의 같은 이름 폴더에 합치므로 겹치는 이름이 있는지 본다(copyOverlaps)
        overwrites = positional.filter(({ j }) => j !== destJ).some(({ w, j }) => copyOverlaps(name, copiesTree, w, argGlobs[j] === true, dest.resolved, base))
      }
      if (overwrites) return { decision: 'ask', reason: REASON.privateRaw }
    }
    return null
  }
  if (name in DOWNLOAD_OUTPUT_OPTIONS) {
    const isOutput = (t) => isDownloadOutput(name, args, t.j)
    if (!targets.every(isOutput)) return { decision: 'ask', reason: REASON.privateOut }
    return targets.some((t) => isRawSpot(t.spot) && mayExist(t)) ? { decision: 'ask', reason: REASON.privateRaw } : null
  }
  // git의 읽기만 하는 하위 명령(log · show · diff …)은 넣지도 보내지도 않는다 — _core는 gitignore라 읽어도 해롭지 않다(2026-10-12 리허설 2차 21)
  if (name === 'git' && !gitEnv && gitReadsOnly(args)) return null
  // git(넣기), gh·scp·rsync(보내기), 인터프리터와 그 밖의 명령은 판정할 수 없다
  return { decision: 'ask', reason: REASON.privateOut }
}

/**
 * 셸 명령을 단순 명령 단위로 나눈다. 완전한 셸 파서가 아니라 이 훅의 판정에 필요한 만큼만 —
 * 따옴표를 존중해 단어를 자르고, 출력 리디렉션 대상(쓰기)은 따로 모은다. 입력 리디렉션 대상은 단어로 본다(읽기).
 * heredoc 본문은 명령 줄이 아니라 그 명령의 입력이므로 단어로 자르지 않고 통째로 붙여 둔다.
 * 구분자에 따옴표가 없는 heredoc(<<EOF)은 셸이 본문의 $(…)·`…`를 펼쳐 실행하므로 expandingHeredocs에 따로 모은다.
 * here-string(<<< 글)은 예전처럼 단어로 두고, 셸이 받으면 명령 줄이 되므로 herestrings에도 적는다(5 · 6번, 2026-10-13).
 * 파이프(|, |&)로 다음 명령에 출력을 넘기는 명령은 pipedOut으로 표시한다 (||는 파이프가 아니다).
 * 파이프 말고도 출력이 다른 명령으로 가는 꼴 — 명령 치환 뒤에 온 파이프(`echo a $(date) | xargs cat`: 파이프가 치환 뒤의 빈 명령에 붙는다)와
 * 프로세스 치환으로 보내기(`echo a > >(xargs cat)`) — 은 feedsCommand로 표시한다. 1번의 echo · printf 판정만 쓴다 (2026-10-13).
 * 큰따옴표 안의 명령 치환은 나누면서 적어 둔 큰따옴표 자리(quoted)에서 찾는다(quotedBodies — 나누기와 같은 따옴표 · 주석 판정, 2026-10-13 4차).
 * globs는 words와 같은 순서로, 그 단어에 따옴표 밖의 * ? [ 가 있었는지 적는다. 따옴표 안의 글자와 \ 바로 뒤의 글자는
 * 셸이 펼치지 않으므로 세지 않는다 (sed 's/.*=//'는 글롭이 아니고, cat ".env"*는 글롭이다).
 *
 * 줄 이음(\ + 줄바꿈)은 셸처럼 통째로 지운다 — 따옴표 밖과 큰따옴표 안에서. 작은따옴표 · $'…' 안은 글자 그대로이고, 주석(낱말 머리의 # 부터 줄 끝) 속의
 * \ + 줄바꿈은 이음이 아니라 그 줄바꿈에서 명령이 끝난다(bash · zsh · dash · ksh 실측). 예전에는 \ 뒤의 줄바꿈을 낱말에 붙여 명령 이름이 "\ngit" · "\nop"가 되어
 * 이름으로 보는 판정을 모두 비켜 갔다(`cd x && \⏎git commit --no-verify`, `git \⏎push origin main`). 이음은 낱말에서 빼고, 앞뒤 글자를 볼 때도 건너뛴다
 * (&& · || · $( · $'…' · <<- — skipJoins · charBefore). 큰따옴표 자리는 날 글의 자리다 — "$(…)" 안의 heredoc 본문은 날 글이라야 끝 줄이 맞는다
 * (quotedSubstitutions가 $\⏎( 도 이어 본다). heredoc 본문도 날 글 그대로 두고(셸에 넘긴 본문은 다시 나눌 때 이음을 지운다), 따옴표 없는 heredoc(<<EOF)의 끝은
 * 날 줄로 맞는 곳(dash · ksh)과 이은 줄로 맞는 곳(bash · zsh: `E\⏎OF`) 가운데 먼저 오는 쪽이다 — 본문을 짧게 보아 실행되는 명령을 본문에 숨기지 못하게.
 * 주석 속 글은 예전처럼 낱말로 나눠 보되(셸이 주석으로 읽지 않는 경우까지 넓게), 다음 줄로 넘어가는 것은 막는다 — 주석 속의 << 는 heredoc이 아니고, 따옴표는
 * 같은 줄에서 닫힐 때만 연다(`# don't⏎git push origin main`, `# x <<sh⏎cat .env.local`의 둘째 줄은 셸이 돌린다). 닫히는지는 \" 를 건너뛰고 본다
 * (`# "a\"⏎git config …`의 둘째 줄도 셸이 돌린다). 값을 펼치는 ${…} 안의 # 은 주석이 아니다(`echo ${x:- #} 'a⏎b'; git config …` — 2026-10-13 4차).
 * $'…'(ANSI-C 따옴표)는 escape를 푼 글을 낱말로 두고(ansiCQuote — `$'git' commit --no-verify`, `$'core.\x68ooksPath'`), $"…"는 "…"와 같다(bash · ksh).
 * ansiC가 false면 예전처럼 $ 를 글자로 둔다 — 그렇게 읽는 셸(dash · Debian의 sh, zsh 의 $"…")을 위해 splitModes가 두 꼴을 함께 본다. decoded: 이번에 푼 것이 있었는가.
 * 명령 치환(`…` · $(…) · <(…) · >(…))이 바깥 명령의 낱말 자리를 끊으면 그 명령에 cut('word', 앞 낱말에 붙었으면 'glued')을 적는다 — 그 자리에 치환의
 * 출력이 든다. 5번이 `git config core.hooksPath \`mktemp -d\``를 값 없는 조회로 읽지 않게 쓴다(withSubstitution)
 * (2026-10-13 총괄 — jarvis 비교 도구 2차)
 *
 * merge(5 · 6번의 argvModes): 셸이 명령에 넘기는 인자 그대로 나눈다 — 명령 치환은 바깥 명령을 끊지 않고 그 자리에 SUBSTITUTED 를 이어 쓰고(`git -C $(pwd) config …`의
 * 이름이 git, 치환 뒤의 낱말도 그 명령의 인자), 낱말에 붙은 프로세스 치환은 한 낱말이고(bash · zsh: `.githooks<(true)`), 입력 리디렉션 대상과 here-string 은
 * 인자에서 뺀다(`git config core.hooksPath <<<.githooks /tmp/hooks`의 값은 /tmp/hooks). 치환 속 명령은 바깥 명령보다 먼저 나온다(셸이 먼저 돌린다).
 * argvDiffers: 두 꼴이 다를 수 있는가(따옴표 밖의 명령 치환 · 입력 리디렉션 · here-string이 있었다). 그 밖의 나누기는 같다 (2026-10-13 4차 — 원칙 검토)
 * 단순 명령마다 scope(열린 서브셸 — ( … ) · $( … ) · <( … ) · `…` — 의 번호 길)와 background(홀로 쓴 & 로 뒤에서 돎)를 적는다 —
 * 대입이 어디까지 닿는지 resolveShellVars가 본다(`(export X=y); cat .env$X`의 X는 밖에서 비어 있다)
 */
function splitCommands(command, ansiC = true, merge = false) {
  const segments = []
  const empty = () => ({
    words: [], globs: [], outputs: [], heredocs: [], expandingHeredocs: [], herestrings: [],
    // 낱말마다(words · outputs · herestrings 와 같은 차례) 그 안에 글자 그대로의 $ 가 있는가 — 작은따옴표 · $'…' · \$ 의 $ 는 셸이 펼치지 않는다.
    // fixed: words 가운데 $ 가 모두 글자 그대로인 낱말(펼칠 것이 없다 — 5 · 6번이 값을 모르는 낱말로 보지 않는다, fixedWords)
    literal: [], fixed: [], outputLiteral: [], herestringLiteral: [],
    pipedOut: false, feedsCommand: false, inParen: false, cut: null, scope: '', background: false,
  })
  // 괄호 · 명령 치환 안인가 — ( … ), $( … ), <( … ), `…` 안의 명령은 출력이 바깥 명령으로 갈 수 있다(inParen, 2026-10-13)
  let parenDepth = 0
  let inBacktick = false
  // 열린 괄호 · ` 마다 { outer, hold } — outer: 명령 치환($( … ) · <( … ) · >( … ) · `…`)이 끊은 바깥 명령(치환이 아니면 null). 치환이 닫힌 뒤 다음 구분자까지는
  // 그 명령이라, 그 사이의 파이프는 바깥 명령의 출력을 넘긴다(feedsCommand). resumed는 방금 닫힌 치환의 것.
  // hold(merge): 붙들어 둔 바깥 명령과 그 낱말 — 치환이 닫히면 돌아가 이어 쓴다
  const opened = []
  let resumed = null
  // 열린 서브셸의 번호 길(/1/3) — 그 안의 대입은 밖에 닿지 않는다(scope). 열고 닫을 때마다 고쳐 둔다(깊이 겹쳐도 단순 명령마다 잇지 않게)
  let scope = ''
  let scopeCount = 0
  const openScope = () => {
    scope = `${scope}/${++scopeCount}`
  }
  const closeScope = () => {
    scope = scope.slice(0, scope.lastIndexOf('/'))
  }
  let current = empty()
  let cur = ''
  let inWord = false
  let wordQuoted = false // 지금 단어에 따옴표나 \ 가 있었는가 — heredoc 구분자면 본문을 펼치지 않는다
  let wordGlob = false // 지금 단어에 따옴표 밖의 * ? [ 가 있었는가 — 셸은 그것만 글롭으로 펼친다
  let wordLiteral = false // 지금 단어에 글자 그대로의 $ 가 있었는가(작은따옴표 · $'…' · \$) — resolveShellVars 가 펼치지 않는다(`git config core.hooksPath '$V'`)
  let wordDynamic = false // 지금 단어에 셸이 펼치는 $ · ` 가 있었는가(따옴표 밖 · 큰따옴표 안, 치환 자리)
  let quote = null
  let quoteStart = 0
  const quoted = [] // 큰따옴표 안의 [시작, 끝) — 날 글의 자리
  let decoded = false // $'…' · $"…"를 풀었는가 — 풀지 않았으면 $ 를 글자로 두는 꼴(ansiC false)도 같게 나뉜다(splitModes)
  let inComment = false // 낱말 머리의 # 부터 줄 끝까지 — 그 속의 \ + 줄바꿈은 줄 이음이 아니다(낱말은 예전처럼 나눠 본다)
  let braceDepth = 0 // 값을 펼치는 ${…} 안인가 — 그 안의 # 은 주석이 아니다
  let argvDiffers = false
  let redirect = null // 'out' | 'in' | 'herestring' | 'fd' | 'heredoc' | 'heredoc-strip' — 다음 단어가 리디렉션 대상
  let pendingHeredocs = [] // { delimiter, strip, owner, expands } — 다음 줄부터 본문이 온다

  /** k 자리부터 줄 이음(\ + 줄바꿈)을 건너뛴 자리 — 따옴표 밖(주석 밖)에서 다음 글자를 볼 때 쓴다. 글은 고치지 않는다(긴 글에서도 한 번 훑기) */
  const skipJoins = (k) => {
    while (command[k] === '\\' && command[k + 1] === '\n') k += 2
    return k
  }
  const flushWord = () => {
    if (!inWord) return
    if (redirect === 'out') {
      current.outputs.push(cur)
      current.outputLiteral.push(wordLiteral)
    } else if (redirect === 'heredoc' || redirect === 'heredoc-strip') {
      pendingHeredocs.push({ delimiter: cur, strip: redirect === 'heredoc-strip', owner: current, expands: !wordQuoted })
    } else if (redirect !== 'fd') {
      const input = redirect === 'in' || redirect === 'herestring'
      if (input) argvDiffers = true
      // merge: 입력 리디렉션 대상과 here-string 은 셸이 명령에 넘기는 인자가 아니다
      if (!(merge && input)) {
        current.words.push(cur)
        current.globs.push(wordGlob)
        current.literal.push(wordLiteral)
        current.fixed.push(wordLiteral && !wordDynamic)
      }
      if (redirect === 'herestring') {
        current.herestrings.push(cur)
        current.herestringLiteral.push(wordLiteral)
      }
    }
    redirect = null
    cur = ''
    inWord = false
    wordQuoted = false
    wordGlob = false
    wordLiteral = false
    wordDynamic = false
  }
  const flushSegment = (pipedOut = false) => {
    flushWord()
    current.inParen = parenDepth > 0 || inBacktick
    current.pipedOut = pipedOut
    current.scope = scope
    if (pipedOut && resumed !== null) resumed.feedsCommand = true
    if (current.words.length > 0 || current.outputs.length > 0) segments.push(current)
    current = empty()
    redirect = null
  }
  /** merge: 닫힌 치환 자리로 돌아간다 — 붙들어 둔 바깥 명령의 낱말에 치환의 출력(SUBSTITUTED)을 이어 쓴다 */
  const resume = (hold) => {
    current = hold.segment
    cur = `${hold.cur}${SUBSTITUTED}`
    inWord = true
    wordQuoted = hold.wordQuoted
    wordGlob = hold.wordGlob
    wordLiteral = hold.wordLiteral
    wordDynamic = true
    redirect = hold.redirect
  }
  /**
   * 줄바꿈 뒤: 걸려 있는 heredoc 본문을 구분자 줄까지 읽어 주인 명령에 붙이고, 다음 읽을 위치를 돌려준다. 본문은 날 글 그대로 둔다.
   * 날 줄이 구분자면 끝난다(dash · ksh). 따옴표 없는 구분자(expands)의 본문은 줄 이음(끝의 홀수 개 \ + 줄바꿈)으로 이은 줄이 구분자여도 끝난다(bash · zsh: `E\⏎OF`)
   */
  const readHeredocs = (start) => {
    let pos = start
    for (const { delimiter, strip, owner, expands } of pendingHeredocs) {
      const body = []
      let joined = null // 따옴표 없는 본문에서 줄 이음으로 이어 가는 줄(이음을 지운 것)
      const bare = (line) => (strip ? line.replace(/^\t+/, '') : line)
      while (pos <= command.length) {
        const end = command.indexOf('\n', pos)
        const line = command.slice(pos, end === -1 ? command.length : end)
        pos = end === -1 ? command.length + 1 : end + 1
        if (bare(line) === delimiter) break
        if (expands) {
          const logical = (joined ?? '') + bare(line)
          joined = /(^|[^\\])(\\\\)*\\$/.test(line) ? logical.slice(0, -1) : null
          if (joined === null && logical === delimiter) break
        }
        body.push(line)
      }
      const text = body.join('\n')
      owner.heredocs.push(text)
      if (expands) owner.expandingHeredocs.push(text)
    }
    pendingHeredocs = []
    return pos
  }

  for (let i = 0; i < command.length; i++) {
    // 따옴표 밖(주석 밖)의 줄 이음은 셸이 통째로 지운다 — 건너뛴다. 작은따옴표 안은 글자 그대로다
    if (quote === null && !inComment) {
      i = skipJoins(i)
      if (i >= command.length) break
    }
    const c = command[i]
    if (quote) {
      if (c === quote) {
        quote = null
        if (c === '"') quoted.push([quoteStart, i])
      }
      // 큰따옴표 안의 줄 이음도 낱말에서 뺀다 — 큰따옴표 자리는 날 글이라 그 안의 "$(…)"(heredoc 본문까지)를 quotedSubstitutions가 날 글로 다시 읽는다
      else if (c === '\\' && quote === '"' && command[i + 1] === '\n') i++
      else if (c === '\\' && quote === '"' && i + 1 < command.length) {
        if (command[i + 1] === '$') wordLiteral = true
        cur += command[++i]
      } else {
        if (c === '$' && quote === "'") wordLiteral = true
        else if ((c === '$' || c === '`') && quote === '"') wordDynamic = true
        cur += c
      }
      continue
    }
    // 주석 속의 따옴표는 같은 줄에서 닫힐 때만 연다 — 셸에게는 줄 끝까지 글이라, 다음 줄의 명령을 따옴표 안으로 삼키지 않게(`# don't⏎git push …`)
    if ((c === "'" || c === '"') && !(inComment && !closesOnLine(command, i))) {
      quote = c
      quoteStart = i + 1
      inWord = true
      wordQuoted = true
      continue
    }
    if (c === '$' && !inComment) {
      const next = skipJoins(i + 1)
      // 값을 펼치는 ${…} — 닫히는 } 가 있을 때만(셸도 닫히지 않으면 돌리지 않는다)
      if (command[next] === '{' && paramBraceEnd(command, next, ansiC) > next) braceDepth++
      // $'…'(ANSI-C 따옴표) — escape를 푼 글이 낱말에 든다
      if (ansiC && command[next] === "'") {
        const { value, end } = ansiCQuote(command, next + 1)
        cur += value
        if (value.includes('$')) wordLiteral = true
        inWord = true
        wordQuoted = true
        decoded = true
        i = end - 1
        continue
      }
      // $"…"(번역 따옴표)는 "…"와 같다 — $ 를 떼고 큰따옴표로 읽는다
      if (ansiC && command[next] === '"') {
        decoded = true
        i = next - 1
        continue
      }
    }
    if (c === '\\' && i + 1 < command.length) {
      // 주석 속의 \ + 줄바꿈은 줄 이음이 아니다 — \ 는 글자로 두고, 줄바꿈에서 명령이 끝난다
      if (inComment && command[i + 1] === '\n') {
        cur += c
        inWord = true
        continue
      }
      if (command[i + 1] === '$') wordLiteral = true
      cur += command[++i]
      inWord = true
      wordQuoted = true
      continue
    }
    if (c === ' ' || c === '\t') {
      flushWord()
      continue
    }
    if (c === '\n') {
      flushSegment()
      resumed = null
      inComment = false
      if (pendingHeredocs.length > 0) i = readHeredocs(i + 1) - 1
      continue
    }
    if (c === '|') {
      const next = inComment ? i + 1 : skipJoins(i + 1)
      if (command[next] === '|') {
        i = next
        flushSegment()
      } else {
        if (command[next] === '&') i = next
        flushSegment(true)
      }
      resumed = null
      continue
    }
    if (';&()`'.includes(c)) {
      // 출력을 프로세스 치환으로 보내는 것(`> >(xargs cat)`)은 파이프와 같다
      if (c === '(' && redirect === 'out' && !inWord) (resumed ?? current).feedsCommand = true
      const outer = resumed ?? current
      const substitutes = c === '`' ? !inBacktick : c === '(' && '$<>'.includes(inComment ? (command[i - 1] ?? ' ') : charBefore(command, i))
      const opening = c === '(' || (c === '`' && !inBacktick)
      const closing = (c === ')' && parenDepth > 0) || (c === '`' && inBacktick)
      if (substitutes) argvDiffers = true
      // 홀로 쓴 & — 그 명령은 뒤에서(서브셸에서) 돈다. && · &> 는 아니다(>& · |& 는 앞에서 먹는다)
      if (c === '&' && !inComment && !'&>'.includes(command[skipJoins(i + 1)] ?? ' ') && charBefore(command, i) !== '&') current.background = true
      let hold = null
      if (merge && substitutes) {
        // 바깥 명령을 끊지 않고 붙들어 둔다 — $( 의 $ 는 낱말에서 뗀다
        if (c === '(' && cur.endsWith('$') && charBefore(command, i) === '$') cur = cur.slice(0, -1)
        hold = { segment: current, cur, wordQuoted, wordGlob, wordLiteral, redirect }
        current = empty()
        cur = ''
        inWord = false
        wordQuoted = false
        wordGlob = false
        wordLiteral = false
        wordDynamic = false
        redirect = null
      } else {
        // 치환이 바깥 명령의 낱말 자리를 끊는다 — 그 자리에 치환의 출력이 든다(5번이 값으로 본다)
        if (substitutes) current.cut = inWord ? 'glued' : 'word'
        flushSegment()
      }
      resumed = null
      if (opening) {
        if (c === '(') parenDepth++
        else inBacktick = true
        openScope()
        opened.push({ outer: substitutes && hold === null ? outer : null, hold })
      } else if (closing) {
        if (c === ')') parenDepth--
        else inBacktick = false
        closeScope()
        const top = opened.pop()
        if (top?.hold) resume(top.hold)
        else resumed = top?.outer ?? null
      }
      continue
    }
    if (c === '>' || c === '<') {
      // merge: 낱말에 붙은 <( … ) · >( … )는 그 낱말의 일부다(bash · zsh) — 리디렉션이 아니다. ( 에서 치환으로 연다
      if (merge && !inComment && command[skipJoins(i + 1)] === '(') continue
      // 2>, 1>> 의 숫자는 파일 디스크립터라 단어가 아니다
      if (inWord && /^\d+$/.test(cur)) {
        cur = ''
        inWord = false
        wordQuoted = false
        wordGlob = false
        wordLiteral = false
        wordDynamic = false
      } else {
        flushWord()
      }
      let op = c
      for (;;) {
        const next = inComment ? i + 1 : skipJoins(i + 1)
        if (!'<>&|'.includes(command[next] ?? ' ')) break
        op += command[next]
        i = next
      }
      if (op === '<<' && !inComment) {
        // heredoc: <<EOF, <<'EOF', <<-EOF(앞 탭 제거). <<<는 here-string이라 단어로 본다. 주석 속의 << 는 heredoc이 아니다(다음 줄은 명령이다)
        const next = skipJoins(i + 1)
        const strip = command[next] === '-'
        if (strip) i = next
        redirect = strip ? 'heredoc-strip' : 'heredoc'
      } else if (op === '<<<') {
        redirect = 'herestring'
      } else {
        redirect = op.endsWith('&') ? 'fd' : c === '>' ? 'out' : 'in'
      }
      continue
    }
    if (c === '#' && !inWord && braceDepth === 0) inComment = true
    if (c === '}' && braceDepth > 0) braceDepth--
    // 따옴표 앞의 $ 는 $'…' · $"…"를 풀지 않는 셸(dash · zsh 의 $"…")에서 글자 그대로다. 그 밖의 $ 는 셸이 펼친다
    if (c === '$') {
      if (!ansiC && `'"`.includes(command[skipJoins(i + 1)] ?? ' ')) wordLiteral = true
      else wordDynamic = true
    }
    if (c === '*' || c === '?' || c === '[') wordGlob = true
    cur += c
    inWord = true
  }
  if (quote === '"') quoted.push([quoteStart, command.length])
  flushSegment()
  // 닫히지 않은 치환(셸은 돌리지 않는다)도 붙들어 둔 바깥 명령을 버리지 않는다
  while (opened.length > 0) {
    const top = opened.pop()
    closeScope()
    if (top.hold) {
      resume(top.hold)
      flushSegment()
    }
  }
  return { segments, decoded, argvDiffers, quotedBodies: merge ? [] : quotedSubstitutions(command, quoted, ansiC) }
}

/** 따옴표 밖에서 k 바로 앞의 글자 — 줄 이음(\ + 줄바꿈)을 건너뛴다. 맨 앞이면 ' ' */
function charBefore(text, k) {
  let at = k - 1
  while (at > 0 && text[at] === '\n' && text[at - 1] === '\\') at -= 2
  return text[at] ?? ' '
}
/**
 * i 자리의 따옴표가 같은 줄 안에서 닫히는가 — 주석 속 따옴표 판정(splitCommands). 큰따옴표 안의 \" 는 닫지 않는다(따옴표 안의 나누기와 같게) —
 * `# "a\"⏎git config …`에서 따옴표를 열면 둘째 줄을 삼킨다. 큰따옴표 안의 \ + 줄바꿈(다음 줄로 잇기)을 만나면 닫히지 않는다고 본다 (2026-10-13 4차)
 */
function closesOnLine(text, i) {
  const q = text[i]
  for (let k = i + 1; k < text.length; k++) {
    const c = text[k]
    if (c === '\n') return false
    if (q === '"' && c === '\\') {
      if (text[k + 1] === '\n') return false
      k++
      continue
    }
    if (c === q) return true
  }
  return false
}
/** from 부터 다음의 이스케이프되지 않은 ` 자리(없으면 -1) — `…` 의 끝 */
function backtickEnd(text, from) {
  for (let j = from; j < text.length; j++) {
    if (text[j] === '\\') j++
    else if (text[j] === '`') return j
  }
  return -1
}
/**
 * 셸처럼 괄호 · 따옴표를 따라가 kind 로 연 것이 닫히는 자리(없으면 -1) — from 은 연 글자 다음 자리. kind: 'paren'(명령 치환 $( … ) · 괄호 — 안은 명령 줄),
 * 'dq'(큰따옴표 — 안의 $( … ) · ${…} 는 새로 연다), 'brace'(값을 펼치는 ${…}). 명령 줄 안에서는 따옴표(' · " · $'…'), \, `…`, 주석(낱말 머리의 # 부터 줄 끝),
 * heredoc 본문(<<EOF · <<'EOF' · <<-EOF — 다음 줄부터 구분자 줄까지)을 건너뛰고, case … esac 안의 ) 는 패턴의 끝이라 닫지 않는다. ${…} 안의 ( ) 는 글자다.
 * 열린 것을 쌓아 두고 한 번 훑는다 — 서로 부르지 않아 깊이 겹치거나 닫히지 않은 꼴이 많아도 빨리 끝난다 (2026-10-13 4차)
 */
function closingOf(text, from, kind, ansiC = true) {
  const stack = [{ kind, cases: 0, braces: 0 }]
  let atWord = true // 명령 줄에서 낱말 머리인가 — # 이 주석을 열고, case · esac 를 낱말로 본다
  let pending = [] // heredoc 구분자 { delimiter, strip } — 다음 줄부터 본문
  for (let j = from; j < text.length; j++) {
    const top = stack[stack.length - 1]
    const c = text[j]
    if (c === '\\') {
      j++
      atWord = false
      continue
    }
    if (c === '`') {
      const end = backtickEnd(text, j + 1)
      if (end < 0) return -1
      j = end
      atWord = false
      continue
    }
    if (c === '$' && (text[j + 1] === '(' || text[j + 1] === '{')) {
      stack.push({ kind: text[j + 1] === '(' ? 'paren' : 'brace', cases: 0, braces: 0 })
      j++
      atWord = text[j] === '('
      continue
    }
    if (top.kind === 'dq') {
      if (c === '"') {
        stack.pop()
        if (stack.length === 0) return j
        atWord = false
      }
      continue
    }
    if (c === "'") {
      const end = text.indexOf("'", j + 1)
      if (end < 0) return -1
      j = end
      atWord = false
      continue
    }
    if (c === '$' && ansiC && text[j + 1] === "'") {
      j = ansiCQuote(text, j + 2).end - 1
      atWord = false
      continue
    }
    if (c === '"') {
      stack.push({ kind: 'dq' })
      atWord = false
      continue
    }
    if (top.kind === 'brace') {
      if (c === '{') top.braces++
      else if (c === '}' && top.braces > 0) top.braces--
      else if (c === '}') {
        stack.pop()
        if (stack.length === 0) return j
      }
      continue
    }
    // 명령 줄(paren)
    if (c === '#' && atWord) {
      const end = text.indexOf('\n', j)
      if (end < 0) return -1
      j = end - 1
      continue
    }
    if (c === '\n') {
      atWord = true
      for (const { delimiter, strip } of pending) {
        let pos = j + 1
        for (;;) {
          if (pos > text.length) return -1
          const end = text.indexOf('\n', pos)
          const line = text.slice(pos, end < 0 ? text.length : end)
          pos = end < 0 ? text.length + 1 : end + 1
          if ((strip ? line.replace(/^\t+/, '') : line) === delimiter) break
        }
        j = pos - 1
      }
      pending = []
      continue
    }
    if (c === '<' && text[j + 1] === '<' && text[j + 2] !== '<') {
      // heredoc 구분자 — 따옴표 · \ 를 뗀 낱말
      let k = j + 2
      const strip = text[k] === '-'
      if (strip) k++
      while (text[k] === ' ' || text[k] === '\t') k++
      let delimiter = ''
      for (; k < text.length && !/[\s;&|()<>]/.test(text[k]); k++) {
        if (text[k] === "'" || text[k] === '"') {
          const end = text.indexOf(text[k], k + 1)
          if (end < 0) return -1
          delimiter += text.slice(k + 1, end)
          k = end
        } else if (text[k] === '\\') delimiter += text[++k] ?? ''
        else delimiter += text[k]
      }
      if (delimiter !== '') pending.push({ delimiter, strip })
      j = k - 1
      atWord = false
      continue
    }
    if (c === '(') {
      stack.push({ kind: 'paren', cases: 0, braces: 0 })
      atWord = true
      continue
    }
    if (c === ')') {
      atWord = true
      if (top.cases > 0) continue
      stack.pop()
      if (stack.length === 0) return j
      continue
    }
    if (atWord && /[a-z]/.test(c)) {
      const word = /^[a-z]+/.exec(text.slice(j, j + 8))?.[0] ?? ''
      if (/[\s;&|()<>]/.test(text[j + word.length] ?? ' ')) {
        if (word === 'case') top.cases++
        else if (word === 'esac' && top.cases > 0) top.cases--
      }
      j += word.length - 1
      atWord = false
      continue
    }
    atWord = /[\s;&|<>]/.test(c)
  }
  return -1
}
/**
 * 값을 펼치는 ${…}의 닫는 } 자리(없으면 -1) — open 은 { 의 자리. 따옴표 · \ · `…` · $( … ) 안의 } 는 세지 않는다.
 * { 뒤가 빈칸 · 줄바꿈 · | 이면 값 펼치기가 아니라 명령을 돌리는 꼴(ksh93 · bash 5.3 의 ${ 명령; })이라 -1 — 그 안의 # 은 주석이다.
 * 1024 글자 안에서만 찾는다 — 닫히지 않은 ${ 가 많아도 빨리 끝나게(못 찾으면 예전처럼 # 을 주석으로 본다)
 */
function paramBraceEnd(text, open, ansiC = true) {
  if (/[\s|]/.test(text[open + 1] ?? ' ')) return -1
  return closingOf(text.slice(0, open + 1024), open + 1, 'brace', ansiC)
}
/**
 * 명령 치환 $( … )의 닫는 ) 자리(없으면 text.length) — open 은 ( 의 자리. 셸처럼 그 안을 명령 줄로 훑는다(closingOf): 따옴표(' · " · $'…'), \, `…`, ${…},
 * 주석, heredoc 본문, 안의 괄호, case … esac 의 패턴. 예전에는 괄호만 세어 따옴표 안의 ) 에서 끝났다(`"$(echo ')'; git config core.hooksPath /tmp/hooks)"`의
 * 뒤를 놓침, 2026-10-13 4차 — 원칙 검토). 못 찾으면 끝까지 — 모르는 꼴에서는 늦게 끝나는 쪽이 낫다(치환의 몸은 명령으로 다시 판정한다)
 */
function matchParen(text, open, ansiC = true) {
  const end = closingOf(text, open + 1, 'paren', ansiC)
  return end < 0 ? text.length : end
}

/** $'…' 안의 escape 가운데 한 글자로 바뀌는 것 */
const ANSI_C_ESCAPES = { a: '\x07', b: '\b', e: '\x1b', E: '\x1b', f: '\f', n: '\n', r: '\r', t: '\t', v: '\v', '\\': '\\', "'": "'", '"': '"', '?': '?' }
/**
 * $'…'(ANSI-C 따옴표)의 글 — start는 여는 따옴표 다음 자리. { value, end(닫는 따옴표 다음 자리) }.
 * escape를 푼다: \a \b \e \f \n \r \t \v \\ \' \" \?, \NNN(8진 1~3자리), \xHH(16진 1~2자리), \uHHHH · \UHHHHHHHH, \cX(제어 글자).
 * 셸마다 다른 곳은 이름이 드러나는 쪽으로 푼다 — 모르는 escape는 \ 를 뗀다(zsh · ksh: `$'\git'`은 git), \x · \u 뒤에 16진 숫자가 없으면 지운다(ksh),
 * NUL(\0 · \x00)이 나오면 그 따옴표의 남은 글을 버린다(bash · ksh: `$'git\0x'`는 git). \ + 줄바꿈은 줄 이음이 아니라 줄바꿈이다 (2026-10-13 총괄)
 */
function ansiCQuote(text, start) {
  let value = ''
  let ended = false
  let i = start
  for (; i < text.length && text[i] !== "'"; i++) {
    let ch = text[i]
    if (ch === '\\' && i + 1 < text.length) {
      const rest = text.slice(i + 1, i + 10)
      let m
      if ((m = /^[0-7]{1,3}/.exec(rest))) ch = String.fromCharCode(parseInt(m[0], 8) & 0xff)
      else if ((m = /^x([0-9A-Fa-f]{0,2})/.exec(rest)) || (m = /^u([0-9A-Fa-f]{0,4})/.exec(rest)) || (m = /^U([0-9A-Fa-f]{0,8})/.exec(rest))) {
        const point = m[1] === '' ? -1 : parseInt(m[1], 16)
        ch = point >= 0 && point <= 0x10ffff ? String.fromCodePoint(point) : ''
      } else if ((m = /^c[\s\S]/.exec(rest))) ch = String.fromCharCode(m[0].charCodeAt(1) & 0x1f)
      else {
        m = [rest[0]]
        ch = ANSI_C_ESCAPES[rest[0]] ?? rest[0]
      }
      i += m[0].length
    }
    if (ch === '\0') ended = true
    if (!ended) value += ch
  }
  return { value, end: i + 1 }
}

/**
 * 큰따옴표 안의 명령 치환 $(…)·`…` — 셸이 실행하므로 따로 검사한다. regions 는 splitCommands 가 나누며 적은 큰따옴표 자리라 따옴표 · 주석 · $'…' 판정이
 * 나누기와 같다(예전에는 따로 훑어 `echo \ # "⏎$(cat .env.local)"`의 \ 뒤 빈칸을 낱말 사이로 보고 # 을 주석으로 읽어 치환을 놓쳤다, 2026-10-13 4차).
 * 따옴표 밖의 치환은 splitCommands가 괄호에서 나누므로 이미 보이고, 작은따옴표 안은 글자 그대로다. 큰따옴표 안의 줄 이음은 $ 와 ( 사이에 있어도 치환이다 —
 * "$\⏎(cat .env.local)". 치환의 끝은 matchParen 이 셸처럼 찾는다(따옴표 친 괄호 · heredoc 본문). 몸이 그 큰따옴표 자리 밖까지 가면(몸 속의 " 에서 나누기가
 * 따옴표를 닫았다) 뒤의 자리는 몸 다음부터 본다
 */
function quotedSubstitutions(command, regions, ansiC = true) {
  const found = []
  let pos = 0
  for (const [start, end] of regions) {
    let k = Math.max(start, pos)
    for (; k < end; k++) {
      const c = command[k]
      if (c === '\\') {
        k++
        continue
      }
      if (c === '`') {
        const close = backtickEnd(command, k + 1)
        if (close < 0) return found
        found.push(command.slice(k + 1, close))
        k = close
        continue
      }
      let open = k + 1
      while (c === '$' && command[open] === '\\' && command[open + 1] === '\n') open += 2
      if (c === '$' && command[open] === '(') {
        const close = matchParen(command, open, ansiC)
        found.push(command.slice(open + 1, close))
        k = close
      }
    }
    pos = Math.max(pos, k)
  }
  return found
}

/**
 * 따옴표 없는 heredoc(<<EOF) 본문의 명령 치환 $(…)·`…` — 셸이 펼쳐 실행한다.
 * 본문에서는 따옴표가 치환을 막지 못하므로 따옴표와 상관없이 찾는다. \ 뒤의 글자는 글자 그대로다.
 * 셸은 이 본문의 줄 이음(\ + 줄바꿈)을 지우고 펼치므로 $ 와 ( 사이의 이음도 치환이다 — `$\⏎(cat .env.local)` (2026-10-13 총괄).
 * 치환 안은 명령 줄이라 끝을 matchParen 이 셸처럼 찾는다(2026-10-13 4차)
 */
function heredocSubstitutions(body) {
  const found = []
  for (let i = 0; i < body.length; i++) {
    const c = body[i]
    if (c === '\\') {
      i++
      continue
    }
    if (c === '`') {
      const end = backtickEnd(body, i + 1)
      if (end === -1) break
      found.push(body.slice(i + 1, end))
      i = end
      continue
    }
    let open = i + 1
    while (c === '$' && body[open] === '\\' && body[open + 1] === '\n') open += 2
    if (c === '$' && body[open] === '(') {
      const end = matchParen(body, open)
      found.push(body.slice(open + 1, end))
      i = end
    }
  }
  return found
}

/**
 * 셸 — 실행하는 heredoc 본문을 명령 줄처럼 나눠 판정할 수 있다. 나머지 인터프리터의 본문은 판정할 수 없다.
 * bash · sh · zsh 밖의 셸(dash · ksh · mksh · ash · busybox의 sh · ash · hush …)과 -c 로 명령 줄을 받는 csh · tcsh · fish 도 셸로 본다 —
 * `dash -c '…'`, `ksh <<'EOF'`, `… | dash`, `busybox sh -c '…'`(셸 낱말을 인자에서 찾는다) (2026-10-13 총괄 — jarvis 비교 도구 2차)
 */
const SHELLS = new Set([
  'bash', 'sh', 'zsh', 'dash', 'ksh', 'ksh93', 'mksh', 'pdksh', 'oksh', 'loksh', 'ash', 'hush', 'yash', 'posh', 'rbash',
  'csh', 'tcsh', 'fish',
])
/** heredoc 본문을 프로그램으로 실행하는 명령 — 이때만 본문 속 .env 참조를 본다 (cat·git의 본문은 데이터다) */
const INTERPRETERS = new Set([...SHELLS, 'node', 'tsx', 'deno', 'bun', 'python', 'python3', 'ruby', 'perl', 'psql'])

/**
 * 스크립트 코드가 파일을 쓰거나 지우거나 옮기는가 — 글자로만 본다 (2026-10-09). 기획 자료를 가리키는 스크립트가 이것에 걸리면
 * 묻지 않고 막고 Edit·Write 도구를 쓰라고 알린다(공통 규칙 8번을 글로 적어도 에이전트가 python으로 고쳐 확인 창이 계속 떴다, eyeson).
 * 화면에 내는 것(print, sys.stdout.write)은 보지 않는다. 여기 걸리지 않는 쓰기(하위 프로세스 등)는 예전처럼 사용자에게 묻는다
 */
const WRITE_CODE = [
  /\.write_(?:text|bytes)\s*\(/, // pathlib
  /(?<!stdout|stderr)\.write(?:lines)?\s*\(/, // 열어 둔 파일에 쓰기
  /\bopen\s*\([^)]*,\s*(?:mode\s*=\s*)?['"][rbt]*[wax+][rbt+]*['"]/, // open(경로, 'w')
  /\bopen\s*\(?\s*(?:my\s+)?[$\w]+\s*,\s*['"]\+?>{1,2}/, // perl open(my $f, '>', …)
  /\bshutil\./,
  /\bos\.(?:replace|rename|renames|remove|unlink|rmdir|removedirs|makedirs|mkdir)\s*\(/,
  /\.(?:unlink|rmdir|touch|mkdir)\s*\(/, // pathlib
  /\.to_(?:csv|excel|json|parquet|markdown|html)\s*\(/, // pandas
  /\bfs(?:\.promises)?\.(?:writeFile|appendFile|rm|unlink|rename|copyFile|cp|mkdir|rmdir|truncate)\b/,
  /\b(?:writeFile|appendFile|unlink|rename|copyFile|rm|mkdir|rmdir|truncate)Sync\s*\(/,
  /\bcreateWriteStream\s*\(/,
  /\bFile(?:Utils)?\.(?:write|open|delete|rename|unlink|rm|mv|cp)\b/, // ruby
]
function writesFiles(code) {
  return WRITE_CODE.some((re) => re.test(code))
}
/** 인터프리터에 인자로 넘긴 코드(python -c, node -e·-p, ruby·perl -e). 없으면 null. perl·ruby의 -i(그 자리에서 고치기)는 쓰기로 본다.
 *  perl · ruby 는 묶은 꼴(-ne · -lne · -pe)의 코드도 본다 (2026-10-15 R-168 — 예전에는 -e 가 홀로일 때만 보아 `perl -ne 'open …'`이 막히지 않고 물음).
 *  -i 는 글자 옵션 묶음 속의 i 만 센다 — 값을 받는 옵션(-M · -I · -F · -C)의 값 속 i 는 아니다(`perl -Mstrict -ne …`가 그 자리 고치기로 막히던 것, R-168) */
function inlineCode(name, args) {
  if ((name === 'perl' || name === 'ruby') && args.some((a) => /^-[npalwWXtTsScuUvhg0-9]*i/.test(a))) return 'File.write(-i)'
  const flags = name.startsWith('python') ? ['-c'] : name === 'perl' ? ['-e', '-E'] : ['-e', '--eval', '-p', '--print']
  const bundled = name === 'perl' || name === 'ruby' ? /^-[npalwWXtT0-9]+[eE]$/ : null
  for (let i = 0; i < args.length - 1; i++) if (flags.includes(args[i]) || bundled?.test(args[i])) return args[i + 1]
  return null
}

/**
 * 읽기만 하는 perl · awk 한 줄 프로그램인가 (2026-10-15 R-168 — jarvis 세션이 `_core`를 `perl -CSD -Mutf8 -ne` · `awk`로 읽다 권한 요청이 열한 번 떴다).
 * 프로젝트 문서 판정(3번)에서 cat · grep 처럼 읽기만 하는 명령으로 본다. 보수적으로 본다 — 코드를 명령 줄에서 받고(perl 의 -e · -E, awk 의 첫 인자),
 * 파일을 쓰거나 · 명령을 돌리거나 · 밖으로 보내거나 · 이름을 글로 지어 부르는 길이 글자에 하나도 없을 때만이다. perl 은 문자열 · 정규식 속 글자까지 모두 본다
 * (그 속의 낱말 때문에 물을 수는 있어도, 코드를 문자열로 잘못 보아 놓치지는 않게). 판정할 수 없으면 null(예전처럼 묻는다).
 * 돌려주는 것: 코드가 든 인자의 차례(args 기준) — 그 인자는 경로가 아니라 코드라서 그 속의 `_core` 글자는 대상으로 세지 않는다
 */
const PERL_FLAGS = new Set(['n', 'p', 'a', 'w', 'W', 'X', 't', 'T'])
const PERL_PRAGMAS = new Set(['utf8', 'strict', 'warnings'])
/** perl 코드에 이것이 하나라도 있으면 읽기만 한다고 보지 않는다 — 쓰기 · 실행 · 보내기, 이름을 글로 짓는 참조, 다른 꾸러미 · 메서드, 코드 싣기 */
const PERL_RISKY = [
  /`/, // 역따옴표 — 명령을 돌린다
  /\$\^|\$\s*\{\s*\^/, // $^I(그 자리에서 고치기) 같은 특수 변수
  /::|->/, // 다른 꾸러미의 함수 · 메서드(IO::File->new, CORE::GLOBAL::…)
  /[$@%&*]\s*\{/, // 글로 지은 이름의 참조 — ${"…"} · @{"ARGV"} · &{"…"} · *{"…"}
  /[$@%&*]\s*\$[\w{:$]/, // 변수에 든 이름의 참조 — $$x · @$x · & $f · *$g (빈칸을 두어도 된다, perl 5.34 실측)
  /\b(?:system|exec|qx|readpipe|fork|kill|syscall|pipe|open|sysopen|dbmopen|dbmclose|unlink|rename|mkdir|rmdir|link|symlink|chmod|chown|chroot|utime|truncate|chdir|eval|require|dump|tie|socket|socketpair|connect|bind|listen|accept|shutdown|send|recv|setsockopt|syswrite|write|fcntl|ioctl)\b/,
  /\b(?:msg|shm|sem)(?:get|snd|rcv|ctl|read|write|op)\b/,
  /\bget(?:host|net|proto|serv|addr|name)\w*/, // 이름 풀기(DNS)로 밖에 보내기
  /\bnew\w*\s*[${]/, // 간접 객체 꼴의 만들기(new $class …) — 파일 핸들에 메서드를 부르면 IO::File 이 실린다(flush STDOUT, perl 5.34 실측)
  /\bdo\b(?!\s*\{)/, // do FILE — 다른 파일의 코드를 돌린다(do { … } 묶음은 그대로)
  /\b(?:use|no)\b(?!\s+(?:utf8|strict|warnings)\b)/, // 모듈 싣기
  // s///ee — 바꾼 결과를 다시 코드로 돌린다. 꼬리는 닫는 구분자 바로 뒤의 글자들이다(s{…}{…}ee · s'…'…'ee). 낱말 구분자(s xbxBx)와
  // 주석 뒤의 구분자(s #…⏎/…/ee)는 s 뒤의 빈칸 · # 로 본다(perl 5.34 실측). 정규식 속 영어 낱말(|release|)도 걸릴 수 있다 — 그때는 묻는다
  /[^\w\s][msixpodualngcer]*e[msixpodualngcer]*e[msixpodualngcer]*(?!\w)/,
  /(?<![\w$@'])s\s+\w|(?<![\w$@'])s\s*#/,
]
/** perl 코드의 ARGV 는 지금 읽는 파일 이름($ARGV)과 닫기 · 끝 · 읽기(close ARGV · eof(ARGV) · <ARGV>)만 둔다 —
 *  @ARGV 를 바꾸면 -n · -p 의 <> 가 그 이름을 2-인자 open 으로 연다('>x'는 쓰기, 'x|'는 실행) */
function perlArgvOk(text) {
  for (const m of text.matchAll(/\bARGV\w*/g)) {
    const before = text.slice(0, m.index)
    const after = text.slice(m.index + m[0].length)
    if (m[0] !== 'ARGV') return false
    if (/\$$/.test(before) && !/^\s*[[{]/.test(after)) continue
    if (/<$/.test(before) && after.startsWith('>')) continue
    if (/\b(?:close|eof)\s*\(?\s*$/.test(before)) continue
    return false
  }
  return true
}
function perlReadsOnly(args, isGlob) {
  const code = []
  const codeAt = new Set()
  let files = args.length
  for (let i = 0; i < args.length; i++) {
    const a = args[i]
    if (a === '--') {
      files = i + 1
      break
    }
    if (a === '-' || !a.startsWith('-')) {
      if (code.length === 0) return null // 스크립트 파일을 돌린다
      files = i
      break
    }
    // 묶은 꼴(-CSD · -lne · -F'\t' · -0777)을 perl 처럼 한 글자씩 읽는다. 코드 뒤의 옵션도 perl 이 읽는다(`-ne '…' -i`는 그 자리에서 고침, 실측)
    for (let k = 1; k < a.length; k++) {
      const c = a[k]
      const next = () => a[k + 1] ?? ''
      if (PERL_FLAGS.has(c)) continue
      if (c === 'l') {
        while (/[0-7]/.test(next())) k++
        continue
      }
      if (c === '0') {
        if (/[xX]/.test(next())) for (k++; /[0-9a-fA-F]/.test(next()); ) k++
        else while (/[0-7]/.test(next())) k++
        continue
      }
      if (c === 'C') {
        // 숫자 아니면 글자 묶음. i 는 넣지 않는다(-C 의 글자이기도 하지만 -i 로 읽힐 수 있는 꼴은 묻는다)
        if (/\d/.test(next())) while (/\d/.test(next())) k++
        else while (/[IOESoDALa]/.test(next())) k++
        continue
      }
      if (c === 'F') {
        code.push(a.slice(k + 1)) // 나누는 패턴도 코드처럼 본다(정규식 속 코드 묶음)
        break
      }
      if (c === 'M') {
        if (!PERL_PRAGMAS.has(a.slice(k + 1))) return null
        break
      }
      if (c === 'e' || c === 'E') {
        if (k + 1 < a.length) {
          code.push(a.slice(k + 1))
          codeAt.add(i)
        } else {
          if (i + 1 >= args.length) return null
          i++
          code.push(args[i])
          codeAt.add(i)
        }
        break
      }
      return null // -i · -x · -I · -m · -d · -s · -S … 와 모르는 옵션
    }
  }
  if (code.length === 0) return null
  // -n · -p 의 <> 는 파일 이름을 2-인자 open 으로 연다 — '>x' · '+<x'는 쓰기, 'x|' · '|x'는 실행. 값을 모르는 이름(변수 · 치환 · 글롭)도 묻는다
  for (let j = files; j < args.length; j++) {
    const f = args[j]
    if (f === '-') continue
    if (f === '' || /[$`|<>&]/.test(f) || /^\s|\s$/.test(f) || isGlob(j)) return null
  }
  const text = code.join('\n').replace(/&&|\|\|/g, '  ')
  if (PERL_RISKY.some((re) => re.test(text)) || !perlArgvOk(text)) return null
  return codeAt
}

/**
 * awk 의 프로그램(첫 인자)이 읽기만 하는가 — 문자열과 정규식을 걷어 낸 코드에 명령 실행(system · | · getline), 동작 속의 출력 돌리기(> · >>),
 * gawk 지시(@)가 없을 때만. 옵션은 -F · -v · -- 만 둔다(gawk 의 -i inplace · -f · -l · -o · -p · -d 등은 묻는다). 판정할 수 없으면 null.
 * 돌려주는 것은 perlReadsOnly 와 같다(프로그램이 든 인자의 차례)
 */
const AWKS = new Set(['awk', 'gawk', 'mawk', 'nawk'])
/** 그 뒤의 / 가 나누기가 아니라 정규식인 awk 낱말 */
const AWK_REGEX_KEYWORDS = new Set(['print', 'printf', 'return', 'in', 'getline', 'do', 'else', 'case', 'delete', 'exit'])
function awkReadsOnly(args) {
  let i = 0
  for (; i < args.length; i++) {
    const a = args[i]
    if (a === '--') {
      i++
      break
    }
    if (!a.startsWith('-') || a === '-') break
    if (a === '-F' || a === '-v') i++
    else if (!/^-[Fv]./.test(a)) return null
  }
  if (i >= args.length) return null
  const code = awkCode(args[i])
  if (code === null) return null
  if (/\b(?:system|getline)\b|@|\|/.test(code.replace(/\|\|/g, '  '))) return null
  // 동작({ … }) 안에서 괄호 밖의 > 는 출력 돌리기다(print > "f" · printf … >> f). 무늬(동작 밖)와 괄호 안의 > 는 견주기, >= 는 늘 견주기
  let brace = 0
  const paren = []
  for (let k = 0; k < code.length; k++) {
    const c = code[k]
    if (c === '{') {
      brace++
      paren.push(0)
    } else if (c === '}') {
      brace--
      paren.pop()
      if (brace < 0) return null
    } else if (c === '(' && brace > 0) paren[paren.length - 1]++
    else if (c === ')' && brace > 0) paren[paren.length - 1]--
    else if (c === '>' && code[k + 1] !== '=' && brace > 0 && paren[paren.length - 1] <= 0) return null
  }
  return new Set([i])
}
/**
 * awk 프로그램에서 문자열("…")과 정규식(/…/)을 걷어 낸 코드. 판정할 수 없으면 null — 줄을 넘는 문자열 · 정규식, 주석(#), 문자열 속의 / 와
 * 정규식 속의 "(문자열과 정규식의 경계를 잘못 보아 코드를 걷어 내지 않게), 나누기인지 정규식인지 모르는 ) 뒤의 / .
 * / 가 정규식인지는 POSIX awk 처럼 앞 낱말로 가린다 — 값(이름 · 수 · ] · 문자열 · 뒤에 붙은 ++ · --) 뒤는 나누기, 그 밖(연산자 · 줄바꿈 · 시작 ·
 * print 처럼 정규식이 오는 낱말 뒤)은 정규식
 */
function awkCode(program) {
  let out = ''
  let prev = '' // 앞의 뜻 있는 글자(빈칸 뺌, 줄바꿈은 문장 끝)
  let word = '' // 앞 낱말(이름 · 수)
  for (let k = 0; k < program.length; k++) {
    const c = program[k]
    if (c === '\\' && program[k + 1] === '\n') {
      k++
      continue
    }
    if (c === '#') return null
    if (c === '"' || (c === '/' && prev !== ')' && !(/[\w\]"]/.test(prev) && !AWK_REGEX_KEYWORDS.has(word)) && !/(\+\+|--)\s*$/.test(out))) {
      // 문자열이면 / 가, 정규식이면 " 가 속에 있으면 판정하지 않는다
      const other = c === '"' ? '/' : '"'
      let end = k + 1
      for (; end < program.length && program[end] !== c; end++) {
        if (program[end] === '\\') end++
        else if (program[end] === '\n' || program[end] === other) return null
      }
      if (end >= program.length) return null
      out += c + c
      k = end
      prev = '"' // 문자열 · 정규식은 값이다 — 뒤의 / 는 나누기
      word = ''
      continue
    }
    if (c === '/' && prev === ')') return null
    out += c
    if (c === '\n') {
      prev = '\n'
      word = ''
      continue
    }
    if (/\s/.test(c)) continue
    word = /\w/.test(c) ? (/\w/.test(prev) ? word + c : c) : ''
    prev = c
  }
  return out
}

/** xargs의 값을 받는 옵션 — 이 뒤의 단어는 돌릴 명령이 아니라 옵션 값이다 (xargs -I {} rm {}) */
const XARGS_VALUE_OPTIONS = new Set(['-I', '-J', '-L', '-n', '-P', '-s', '-E', '-R', '-S', '-a', '-d'])
/** xargs가 돌리는 명령 — 옵션과 그 값을 건너뛴 첫 단어부터. 없으면 echo를 돌린다(이름 '') */
function xargsCommand(args) {
  let i = 0
  while (i < args.length && (args[i] ?? '').startsWith('-')) i += XARGS_VALUE_OPTIONS.has(args[i]) ? 2 : 1
  return commandOf(args.slice(i))
}
/**
 * 검색 명령(grep · egrep · fgrep · rg · ag · git grep)의 검색어 인자 차례(args 기준) — 경로로 보지 않는다(2026-10-13 apahere).
 * -e · --regexp · -f · --file 이 있으면 그 값이 검색어이고 위치 인자는 모두 파일 · 폴더다. 없으면 첫 위치 인자가 검색어다.
 * 값을 받는 옵션(-A 3, -g '*.ts' …)의 값은 건너뛴다. 도구마다 다르다(grep -r 은 재귀, rg -r 은 바꿀 글). 모르는 옵션은 값을 받지 않는다고 본다 —
 * 틀리면 검색어를 파일로 보아 예전처럼 판정할 뿐, 파일을 검색어로 보아 놓치지는 않는다.
 * git grep 은 하위 명령 grep 뒤의 인자로 같게 본다 — 검색어 뒤의 위치 인자(가지 · 경로)와 -- 뒤의 경로는 그대로 대상이다
 * (`git grep -n -E '_core|_private' -- CLAUDE.md`가 묻던 것, 2026-10-13 4차 — 총괄)
 */
const SEARCH_VALUE_OPTIONS = {
  grep: { short: 'ABCDdefm', long: ['regexp', 'file', 'max-count', 'after-context', 'before-context', 'context', 'include', 'exclude', 'exclude-dir', 'exclude-from', 'label', 'devices', 'directories', 'binary-files', 'group-separator'] },
  rg: { short: 'ABCEefgjMmrTtd', long: ['regexp', 'file', 'glob', 'iglob', 'type', 'type-not', 'type-add', 'type-clear', 'max-count', 'max-depth', 'after-context', 'before-context', 'context', 'encoding', 'replace', 'sort', 'sortr', 'max-columns', 'threads', 'pre', 'pre-glob', 'ignore-file', 'max-filesize', 'path-separator', 'colors', 'context-separator', 'field-match-separator', 'field-context-separator', 'engine', 'dfa-size-limit', 'regex-size-limit'] },
  ag: { short: 'ABCGgm', long: ['ignore', 'ignore-dir', 'file-search-regex', 'depth', 'pager', 'after', 'before', 'context', 'max-count', 'path-to-ignore'] },
  // git grep — -O(페이저)는 붙여 쓴 값만 받는다
  'git grep': { short: 'ABCefm', long: ['max-depth', 'context', 'before-context', 'after-context', 'threads', 'max-count', 'parent-basename'] },
}
function searchPatternArgs(name, args) {
  if (name === 'git') {
    const at = gitSubcommandIndex(args)
    if (at < 0 || args[at] !== 'grep') return new Set()
    return new Set([...searchPatternArgs('git grep', args.slice(at + 1))].map((j) => j + at + 1))
  }
  const tool = name === 'egrep' || name === 'fgrep' ? 'grep' : name
  const spec = SEARCH_VALUE_OPTIONS[tool]
  const found = new Set()
  if (!spec) return found
  const positional = []
  let explicit = false
  for (let j = 0; j < args.length; j++) {
    const a = args[j]
    if (a === '--') { for (let k = j + 1; k < args.length; k++) positional.push(k); break }
    if (a.startsWith('--')) {
      const [key, attached] = [a.slice(2).split('=')[0], a.includes('=')]
      const isPattern = key === 'regexp' || key === 'file'
      if (isPattern) explicit = true
      if (spec.long.includes(key) && !attached) { if (isPattern) found.add(j + 1); j++ }
      else if (isPattern) found.add(j)
      continue
    }
    if (a.startsWith('-') && a.length > 1) {
      for (let c = 1; c < a.length; c++) {
        if (!spec.short.includes(a[c])) continue
        const isPattern = a[c] === 'e' || a[c] === 'f'
        if (isPattern) explicit = true
        if (c < a.length - 1) { if (isPattern) found.add(j) } // 값이 붙음(-e_core, -A3)
        else { if (isPattern) found.add(j + 1); j++ }
        break
      }
      continue
    }
    positional.push(j)
  }
  if (!explicit && positional.length > 0) found.add(positional[0])
  return found
}

/**
 * 검색 명령이 빼는 패턴의 인자 차례(args 기준) — 그 곳은 읽지 않으므로 경로로 보지 않는다(2026-10-13 4차 — jarvis R-120:
 * `rg -n --hidden -g '!.git' -g '!_core' -e x .`가 물음): rg 의 -g · --glob · --iglob 값이 ! 로 시작할 때, ag 의 --ignore · --ignore-dir 값,
 * grep 의 --exclude · --exclude-dir 값, git grep 의 빼는 pathspec(`:!_core` · `:^_core` · `:(exclude)_core`). 고르는 글롭(-g '_core/**' · --include)과
 * 경로 인자, 패턴을 담은 파일(--exclude-from · --ignore-file)은 그대로 대상이다
 */
const SEARCH_EXCLUDE_OPTIONS = {
  rg: { long: ['glob', 'iglob'], short: 'g', negated: true },
  ag: { long: ['ignore', 'ignore-dir'], short: '', negated: false },
  grep: { long: ['exclude', 'exclude-dir'], short: '', negated: false },
}
function searchExclusionArgs(name, args) {
  const found = new Set()
  if (name === 'git') {
    const at = gitSubcommandIndex(args)
    if (at >= 0 && args[at] === 'grep') {
      args.forEach((a, j) => {
        if (j > at && /^:(?:[!^]|\([^)]*\bexclude\b[^)]*\))/.test(a)) found.add(j)
      })
    }
    return found
  }
  const tool = name === 'egrep' || name === 'fgrep' ? 'grep' : name
  const spec = SEARCH_EXCLUDE_OPTIONS[tool]
  const values = SEARCH_VALUE_OPTIONS[tool]
  if (!spec || !values) return found
  const excludes = (value) => !spec.negated || value.startsWith('!')
  for (let j = 0; j < args.length; j++) {
    const a = args[j]
    if (a === '--') break
    if (a.startsWith('--')) {
      const eq = a.indexOf('=')
      const key = (eq < 0 ? a : a.slice(0, eq)).slice(2)
      const takes = spec.long.includes(key) || values.long.includes(key)
      if (eq >= 0) {
        if (spec.long.includes(key) && excludes(a.slice(eq + 1))) found.add(j)
      } else if (takes) {
        if (spec.long.includes(key) && excludes(args[j + 1] ?? '')) found.add(j + 1)
        j++
      }
      continue
    }
    if (a.startsWith('-') && a.length > 1) {
      // 짧은 옵션 묶음 — 값을 받는 첫 글자 뒤(붙었으면 그 나머지, 아니면 다음 낱말)가 그 값이다(-g!_core · -g '!_core')
      for (let c = 1; c < a.length; c++) {
        if (!values.short.includes(a[c])) continue
        const attached = c < a.length - 1
        const value = attached ? a.slice(c + 1) : (args[j + 1] ?? '')
        if (spec.short.includes(a[c]) && excludes(value)) found.add(attached ? j : j + 1)
        if (!attached) j++
        break
      }
    }
  }
  return found
}

/** 반복문 몸에서 아무것도 바꾸지 않는 셸 낱말 */
const LOOP_NOOPS = new Set(['fi', 'esac', 'continue', 'break', 'true', 'false', ':', 'for', 'select'])
/** 파일을 건드리지 않는 셸 낱말 — 반복문 · 조건문의 끝, 입력을 변수로 읽는 read, 예약어만 있는 줄(이름 '') */
const SHELL_SYNTAX = new Set([...LOOP_NOOPS, 'done', 'read', ''])

/**
 * 인자가 글인 명령 — 커밋 메시지, PR·이슈의 제목과 본문. 글 속의 `.env` 글자는 파일 접근이 아니라서 보지 않는다
 * (2026-10-03 easpera-main-home에서 PR 제목 때문에 막힘). 파일 경로로 쓰인 인자(`gh gist create .env.local`,
 * `--body-file=.env.local`, `gh secret set -f .env.local`)는 그대로 막는다.
 */
const TEXT_ARG_COMMANDS = new Set(['git', 'gh'])

/**
 * git·gh의 글 인자 값 — 커밋 메시지(-m, -am, --message), PR·이슈의 제목(-t, --title)과 본문(-b, --body).
 * 그 속의 `_private`·드라이브 경로 글자는 파일이 아니다 (2026-10-04 jarvis에서 커밋 메시지 때문에 확인 창이 뜸).
 * 파일 경로로 쓰인 인자(git add -f _private/…, --body-file, -F <파일>)는 그대로 본다
 */
const TEXT_VALUE_OPTION = /^(-[A-Za-z]*m|--message|-t|--title|-b|--body)$/

/** 명령 앞에 오는 셸 예약어 — `{ op read …; }`, `if op read …; then`도 op 명령으로 판정한다 */
const SHELL_KEYWORDS = new Set(['{', '}', '!', 'if', 'then', 'elif', 'else', 'do', 'while', 'until'])

/**
 * 앞쪽의 환경변수 대입, 셸 예약어, 감싸는 명령(env, sudo …), 패키지 실행기(npx, pnpm exec·dlx …)를 건너뛰고
 * 실제 명령 이름과 인자를 얻는다 — `npx supabase db reset --linked`도 supabase 명령으로 판정한다.
 */
/**
 * 같은 명령 줄에서 앞서 대입한 셸 변수(값에 $·`가 없는 것만)를 뒤 명령의 $이름·${이름}에 풀어 넣고, 대입만 있는 명령에 표시한다 (2026-10-09).
 * `S=_private/a.md; sed -n 1,5p "$S"`처럼 경로를 변수에 담아 읽는 명령이 "판정할 수 없는 명령"으로 걸리던 것(apahere).
 * 대입만 있는 명령은 아무것도 실행하지 않으므로 기획 자료 판정에서 뺀다. export한 변수는 하위 프로그램이 보므로 예전처럼 본다.
 * 내보내거나 선언하는 내장 명령(export · declare · typeset · readonly · local)의 인자로 준 이름=값도 같게 기억한다 — 그 명령 자체는 대입만이 아니라서
 * 예전처럼 판정한다(`export K=core.hooksPath; git config $K /tmp/hooks`, 2026-10-13 총괄 — jarvis 비교 도구 2차).
 * 대입이 닿는 곳은 셸처럼 가린다(2026-10-13 4차 — 원칙 검토): 서브셸(( … ) · $( … ) · `…` · <( … ))·뒤에서 도는 명령(&)·파이프의 명령 안의 대입은 그 밖에 닿지 않는다 —
 * `(export X=y); cat .env$X`의 X는 밖에서 비어 있다(예전에는 밖에서도 y로 풀어 .envy 로 보았다). 파이프의 마지막 명령은 zsh · ksh 에서는 이 셸에서 돌아 값을 모르는 것으로 둔다.
 * 묶음 · 조건 안({ K=…; } · if X=…)과 리디렉션이 붙은 대입(K=… >/dev/null)은 이 셸의 대입이다. unset 은 값을 지우고, X+=값은 덧붙이고, 값을 넣는 내장 명령
 * (read · mapfile · getopts · let · for · select · printf -v)은 그 변수를 모르는 것으로 둔다 — 모르는 변수는 $이름 그대로 남는다(1번은 .env$X 를, 6번은 가지를 모른다고 본다).
 * source · . · eval · 함수 부르기 뒤에는 예전처럼 앞의 값을 그대로 둔다 — 모르는 것으로 두면 3번이 cd "$P" · rm "$S" 의 프로젝트 문서 경로를 놓친다
 */
const ASSIGNMENT = /^([A-Za-z_]\w*)=([\s\S]*)$/
const APPEND = /^([A-Za-z_]\w*)\+=([\s\S]*)$/
const DECLARERS = new Set(['export', 'declare', 'typeset', 'readonly', 'local'])
/** 파일을 건드리지 않는 셸 내장 명령 — 프로젝트 문서 안(cd _core)에서 써도 cat 처럼 본다(인자에 문서 경로가 없을 때만). 3번 판정만 쓴다
 *  (2026-10-15 R-168 — jarvis 서브에이전트의 `cd …/_core && export LC_ALL=en_US.UTF-8; grep …`이 export 때문에 물음) */
const NO_FILE_BUILTINS = new Set([...DECLARERS, 'set', 'unset'])
/** 이름을 받아 값을 넣는 내장 명령 — 무엇이 들지 명령 줄로는 모른다. 이름의 자리: 'all'(인자의 이름 모두) · 숫자(그 차례의 인자) */
const VAR_SETTERS = { read: 'all', mapfile: 'all', readarray: 'all', let: 'all', getopts: 1, for: 0, select: 0 }
const VAR_REFERENCE = /\$(?:\{([A-Za-z_]\w*)\}|([A-Za-z_]\w*))/g
function resolveShellVars(segments) {
  // 대입 기록 { name, scope(닿는 서브셸 길 — splitCommands 의 scope), value(null 이면 모름) } — 뒤의 것이 앞의 것을 가린다
  const records = []
  const lookup = (name, at) => {
    for (let k = records.length - 1; k >= 0; k--) {
      const r = records[k]
      if (r.name === name && (r.scope === '' || at === r.scope || at.startsWith(`${r.scope}/`))) return r.value
    }
    return null
  }
  segments.forEach((segment, i) => {
    const at = segment.scope ?? ''
    const expand = (word) => (word.includes('$') ? word.replace(VAR_REFERENCE, (whole, braced, bare) => lookup(braced ?? bare, at) ?? whole) : word)
    // 글자 그대로의 $ 가 든 낱말(작은따옴표 · $'…' · \$)은 펼치지 않는다 — `V=.githooks; git config core.hooksPath '$V'`의 값은 글자 $V 다 (2026-10-13 4차)
    segment.words = segment.words.map((w, k) => (segment.literal?.[k] ? w : expand(w)))
    segment.outputs = segment.outputs.map((w, k) => (segment.outputLiteral?.[k] ? w : expand(w)))
    segment.herestrings = segment.herestrings.map((w, k) => (segment.herestringLiteral?.[k] ? w : expand(w)))
    // 따옴표 없는 heredoc(<<EOF) 본문도 셸이 변수를 펼친다 — 본문 속 "$S"로 기획 자료에 쓰는 스크립트가 빠지지 않게 (2026-10-10,
    // 설정 적용 세션이 찾은 빈틈). expandingHeredocs는 heredocs 안에서 같은 차례로 들어 있다. 따옴표 친 본문(<<'PY')은 그대로다
    let k = 0
    segment.heredocs = segment.heredocs.map((body) => {
      if (segment.expandingHeredocs[k] !== body) return body
      k++
      return expand(body)
    })
    segment.expandingHeredocs = segment.expandingHeredocs.map(expand)
    segment.assignOnly = segment.words.length > 0 && segment.outputs.length === 0 && segment.words.every((w) => ASSIGNMENT.test(w))

    // 이 명령이 정하는 변수 — 뒤에서 돌거나(&) 파이프의 명령이면 이 셸에 닿는지 모른다
    const detached = segment.background || segment.pipedOut || (i > 0 && segments[i - 1].pipedOut)
    const set = (name, value) => records.push({ name, scope: at, value: detached || value === null || /[$`]/.test(value) ? null : value })
    const assign = (word) => {
      const plain = word.match(ASSIGNMENT)
      if (plain) return set(plain[1], plain[2])
      const append = word.match(APPEND)
      if (append) {
        const before = lookup(append[1], at)
        set(append[1], before === null ? null : `${before}${append[2]}`)
      }
    }
    const { words } = segment
    let first = 0
    while (first < words.length && SHELL_KEYWORDS.has(words[first])) first++
    let end = first
    while (end < words.length && (ASSIGNMENT.test(words[end]) || APPEND.test(words[end]))) end++
    if (end === words.length) {
      // 대입만 있는 명령(묶음 · 조건 안, 리디렉션이 붙어도) — 이 셸의 대입이다
      for (const word of words.slice(first)) assign(word)
      return
    }
    const { name, args } = commandOf(words)
    if (DECLARERS.has(name)) {
      // 옵션과 상관없이 준 값 그대로 기억한다(예전과 같다 — `export -n K=core.hooksPath`도 K 를 정한다)
      for (const a of args) assign(a)
    } else if (name === 'unset') {
      for (const a of args) if (/^[A-Za-z_]\w*$/.test(a)) set(a, null)
    } else if (Object.hasOwn(VAR_SETTERS, name) || (name === 'printf' && /^-v/.test(args[0] ?? ''))) {
      const spot = name === 'printf' ? 'all' : VAR_SETTERS[name]
      const named = spot === 'all' ? args : [args[spot] ?? '']
      for (const a of named) {
        const id = /^[A-Za-z_]\w*/.exec(a.replace(/^-v/, ''))?.[0]
        if (id) set(id, null)
      }
    }
  })
}

function commandOf(words) {
  const wrappers = new Set(['sudo', 'env', 'command', 'time', 'nohup', 'exec'])
  const skipOptions = (from) => {
    let next = from
    while (words[next]?.startsWith('-')) next++
    return next
  }
  let i = 0
  for (;;) {
    const word = words[i]
    if (word === undefined) break
    if (/^[A-Za-z_]\w*=/.test(word) || wrappers.has(word) || SHELL_KEYWORDS.has(word)) i++
    else if (word === 'npx' || word === 'bunx') i = skipOptions(i + 1)
    else if (['pnpm', 'npm', 'yarn'].includes(word) && ['exec', 'dlx'].includes(words[i + 1] ?? '')) i = skipOptions(i + 2)
    else break
  }
  return { name: words[i] ? path.posix.basename(words[i]) : '', args: words.slice(i + 1), program: words[i] ?? '' }
}

/** git 전역 옵션 가운데 값을 다음 낱말로 받는 것 — `--git-dir=…`처럼 = 로 붙이면 한 낱말이다 */
const GIT_GLOBAL_VALUE_OPTIONS = new Set(['-c', '-C', '--git-dir', '--work-tree', '--namespace', '--config-env', '--attr-source', '--super-prefix'])
/**
 * git의 하위 명령 자리 — 앞의 전역 옵션(-c 키=값, -C 경로, --git-dir 경로 …)과 그 값을 건너뛴 첫 단어. 없으면 -1.
 * `--git-dir .git push`의 값을 하위 명령으로 읽으면 push · commit 판정을 비켜 간다 (2026-10-13 총괄 검토)
 */
function gitSubcommandIndex(args) {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] ?? ''
    if (GIT_GLOBAL_VALUE_OPTIONS.has(arg)) i++
    else if (!arg.startsWith('-')) return i
  }
  return -1
}
/** git의 하위 명령 — 앞의 전역 옵션을 건너뛴 첫 단어 */
function gitSubcommand(args) {
  const at = gitSubcommandIndex(args)
  return at < 0 ? '' : (args[at] ?? '')
}
/** 하위 명령 앞의 전역 옵션이 설정을 덮어쓰는가 (-c 키=값, --config-env) — 값 낱말까지 함께 본다 */
function gitOverridesConfig(args) {
  const at = gitSubcommandIndex(args)
  return args.slice(0, at < 0 ? args.length : at).some((a) => /^-c/.test(a) || /^--config-env/.test(a))
}

/**
 * 프로젝트 문서를 넣거나 보내지 않는 git 하위 명령 — 보기만 한다. 넣기 · 커밋 · 옮기기(add · commit · stash · mv · rm · update-index)와
 * 그 밖의 하위 명령은 여기 없으므로 예전처럼 묻는다. 파일에 쓰는 옵션(--output)과 다른 프로그램을 여는 git grep -O는 읽기가 아니다
 */
const GIT_READ_SUBCOMMANDS = new Set([
  'log', 'show', 'diff', 'status', 'blame', 'annotate', 'shortlog', 'whatchanged', 'ls-files', 'ls-tree',
  'rev-parse', 'rev-list', 'check-ignore', 'describe', 'grep', 'cat-file',
])
/**
 * 다른 프로그램을 실행하게 하는 설정은 읽기 명령에 실려도 읽기가 아니다 — 앞쪽 전역 옵션의 설정 덮어쓰기(-c 키=값, --config-env,
 * --exec-path: 페이저 · diff.external · core.fsmonitor …), 외부 diff · 변환 필터(--ext-diff, --textconv, --filters).
 * -C <폴더>는 읽기다. git 앞의 GIT_* · PAGER 환경 변수는 judgePrivate가 gitEnv로 넘긴다 (2026-10-12 총괄 검토).
 * 전역 옵션은 하위 명령 자리까지 모두 본다 — `-C . -c core.pager=…`처럼 -C 의 값 뒤에 와도 설정 덮어쓰기다 (2026-10-13 총괄 검토)
 */
function gitRunsConfiguredProgram(args) {
  const at = gitSubcommandIndex(args)
  if (gitOverridesConfig(args) || args.slice(0, at < 0 ? args.length : at).some((a) => /^--exec-path/.test(a))) return true
  return args.some((a) => /^--(ext-diff|textconv|filters)$/.test(a))
}
function gitReadsOnly(args) {
  if (!GIT_READ_SUBCOMMANDS.has(gitSubcommand(args)) || gitRunsConfiguredProgram(args)) return false
  return !args.some((a) => /^--output(=|$)/.test(a) || /^-O/.test(a) || /^--open-files-in-pager/.test(a))
}
/** git이 읽는 환경 변수(GIT_PAGER · GIT_EXTERNAL_DIFF · GIT_CONFIG_* …)와 PAGER를 대입하는 단어인가 — 앞머리, env, export 모두 */
const GIT_ENV_ASSIGNMENT = /^(GIT_\w*|PAGER)=/

/**
 * `git commit`이 --no-verify로 훅을 건너뛰는가. 긴 옵션은 줄여 써도 된다(--no-verif),
 * 짧은 옵션은 묶을 수 있다(-nm, -anm). 값을 받는 옵션(-m·-F·-C·-c·-t·-u·-S) 뒤의 글자는 그 값이다 (-mn은 메시지 "n").
 */
function skipsCommitHooks(args) {
  return args.some((arg) => {
    if (/^--no-veri/.test(arg)) return true
    const cluster = /^-([A-Za-z]+)$/.exec(arg)?.[1]
    return cluster !== undefined && (cluster.split(/[mFCctuS]/)[0] ?? '').includes('n')
  })
}

/** 커밋 전 검사의 훅 폴더 — 저장소 뿌리의 .githooks(앞의 ./ · 끝의 / 는 같은 곳). git은 core.hooksPath의 상대 경로를 저장소 뿌리 기준으로 푼다 */
const PROJECT_HOOKS_PATH = /^(?:\.\/+)*\.githooks\/*$/
/** git 설정을 환경 변수로 한 번만 덮어쓰는 대입 가운데 설정 이름이 드는 것 — 값에 core.hooksPath가 있으면 `-c core.hooksPath=…`와 같다 */
const GIT_CONFIG_KEY_ASSIGNMENT = /^GIT_CONFIG_(?:PARAMETERS|KEY_\d+)=/

/**
 * 5. 한 명령이 커밋 전 검사를 건너뛰거나 끄는가 — 막을 까닭(REASON.hookBypass · REASON.hooksPath) 또는 null (2026-10-13 사용자 결정 · 총괄 검토).
 * words는 앞머리 대입까지 든 낱말, name · args는 commandOf의 것. 다른 명령이 돌리는 git(timeout 5 git … · nice -n 5 git … · stdbuf -o0 git … ·
 * corepack pnpm exec git … · sudo -u 사용자 git … · xargs git … · find … -exec git … \;)도 6번 push처럼 인자에서 git 낱말을 찾아 본다(wrappedGitCalls,
 * 2026-10-13 총괄 — jarvis 비교 도구가 찾은 빈틈). 셸이 다시 명령 줄로 읽는 글 속은 commitChecksBypassed가 이것을 불러 본다.
 * cut: 명령 치환이 이 명령의 낱말 자리를 끊었는가(splitCommands) — 그 자리를 SUBSTITUTED로 채워 본다. `git config core.hooksPath \`mktemp -d\``는
 * $(…)처럼 값을 준 것이다(예전에는 치환에서 명령이 끊겨 값 없는 조회로 읽었다, 2026-10-13 총괄 — jarvis 비교 도구 2차).
 * 이름을 풀지 못한 변수 · 명령 치환으로 준 명령(`$G commit --no-verify`, `$(echo git) config core.hooksPath /tmp/hooks`)은 git 일 수 있어 git 처럼 본다 (2026-10-13 4차)
 */
function commitCheckBypass(words, name, args, cut = null, fixed = NO_WORDS) {
  // GIT_CONFIG_PARAMETERS · GIT_CONFIG_KEY_n 대입(앞머리 · env · export 모두)에 core.hooksPath가 들면 `-c`와 같다. 글만 내는 명령의 인자는 아니다
  if (!PUSH_TEXT_COMMANDS.has(name) && words.some((w) => GIT_CONFIG_KEY_ASSIGNMENT.test(w) && /core\.hookspath/i.test(w))) return REASON.hookBypass
  const program = words[words.length - args.length - 1] ?? ''
  for (const full of withSubstitution(args, cut)) {
    if (name === 'git' || unresolved(program, fixed)) {
      const found = gitCommitCheckBypass(full, false, fixed)
      if (found !== null) return found
      if (name === 'git') continue
    }
    for (const call of wrappedGitCalls(name, full)) {
      const found = gitCommitCheckBypass(call.args, call.feeders.some((f) => ARG_APPENDERS.has(f)), fixed)
      if (found !== null) return found
    }
  }
  return null
}

/**
 * 명령 치환의 출력이 드는 자리 — 값을 알 수 없다. 5번의 cut 꼴과 5 · 6번의 merge 꼴(argvModes)에 넣는다. 6번은 이 자리 · 풀지 못한 변수로 준 가지를
 * 모르는 가지로 보고 묻는다(pushVerdict — `git push origin \`…\``, `git push origin "$B"`, 2026-10-13 4차)
 */
const SUBSTITUTED = '`…`'
/** 풀지 못한 변수 · 명령 치환이 든 낱말인가 — 값을 모른다. fixed: $ 가 모두 글자 그대로인 낱말들(fixedWords — `'$x'`, dash 의 $'…')은 아니다 */
const NO_WORDS = new Set()
function unresolved(word, fixed = NO_WORDS) {
  return /[$`]/.test(word ?? '') && !fixed.has(word)
}
/**
 * 풀지 못한 변수 · 명령 치환이 든 낱말이 풀린 뒤 그 이름(target, 소문자)이 될 수 있는가 — 그 자리(`…` · $이름 · ${…} · $(…) · `…`)를 아무 글로 보고
 * 나머지 글자와 견준다(대소문자 무시). `core.hooksPath$(true)` · `$(true)core.hooksPath` · `"$K"` · `core.hooks${X}Path`는 core.hookspath 가 될 수 있고,
 * `user.name$(true)`는 아니다 (2026-10-15 R-168 — jarvis 정리 세션 790117ed 의 corpus-jarvis17, 이름에 붙은 명령 치환이 5번을 비켜 감)
 */
function mayBecome(word, target, fixed = NO_WORDS) {
  if (!unresolved(word, fixed)) return false
  const hole = '\u0000'
  const shape = word
    .split(SUBSTITUTED)
    .join(hole)
    .replace(/\$\{[^}]*\}?|\$\((?:[^()]|\([^()]*\))*\)?|`[^`]*`?|\$[A-Za-z_]\w*|\$./g, hole)
    .replace(/\$$/, hole)
  const pattern = shape
    .split(hole)
    .map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
    .join('[\\s\\S]*')
  return new RegExp(`^${pattern}$`, 'i').test(target)
}
/** 단순 명령의 낱말 가운데 $ 가 모두 글자 그대로인 것(splitCommands 의 fixed) — resolveShellVars 뒤에도 그대로다 */
function fixedWords(segment) {
  return segment.fixed?.some(Boolean) ? new Set(segment.words.filter((_, k) => segment.fixed[k])) : NO_WORDS
}
/**
 * 5번이 볼 인자 꼴들 — 늘 받은 그대로를 먼저 보고, 명령 치환이 끊었으면(cut) 그 자리를 SUBSTITUTED로 채운 꼴도 본다.
 * 'word'는 치환이 새 낱말, 'glued'는 마지막 낱말에 붙은 치환이다(그 낱말의 뒤를 모른다 — 출력이 비면 받은 그대로라 둘 다 본다)
 */
function withSubstitution(args, cut) {
  if (cut === 'word') return [args, [...args, SUBSTITUTED]]
  if (cut === 'glued' && args.length > 0) return [args, [...args.slice(0, -1), `${args[args.length - 1]}${SUBSTITUTED}`]]
  return [args]
}

/** 입력에서 받은 낱말을 돌리는 명령의 끝에 붙이는 것 — find -exec 는 {} 자리에만 넣는다 */
const ARG_APPENDERS = new Set(['xargs', 'parallel', 'fd'])
/**
 * git의 인자(args, 하위 명령 포함)가 커밋 전 검사를 건너뛰거나 끄는가 — 까닭 또는 null. appended: 입력에서 받은 낱말을 끝에 붙이는 명령(ARG_APPENDERS)이
 * 돌리는가 — 그러면 값 없이 끝난 `git config core.hooksPath`의 값이 입력에서 오므로(`echo /tmp/hooks | xargs git config core.hooksPath`) 조회가 아니라 바꾸기다
 */
function gitCommitCheckBypass(args, appended, fixed = NO_WORDS) {
  const lower = args.map((a) => a.toLowerCase())
  const subcommand = gitSubcommand(args)
  if (subcommand === 'commit' && skipsCommitHooks(args)) return REASON.hookBypass
  // 한 번만 덮어쓰기 — -c core.hooksPath=…, --config-env core.hooksPath=<변수> · --config-env=core.hooksPath=<변수>
  const overrides = lower.some(
    (a, i) => a.startsWith('--config-env=core.hookspath=') || (a.startsWith('core.hookspath=') && (lower[i - 1] === '-c' || lower[i - 1] === '--config-env')),
  )
  if (overrides) return REASON.hookBypass
  if (subcommand !== 'config') return null
  const configAt = gitSubcommandIndex(args)
  // core 절 지우기 · 이름 바꾸기(--remove-section · --rename-section, 하위 명령 remove-section · rename-section)는 core.hooksPath도 지우거나 바꾼다.
  // 다른 절을 core로 바꿔 넣는 쪽(--rename-section foo core)도 같다
  const sectionAction =
    lower.some((a) => a === '--remove-section' || a === '--rename-section') || ['remove-section', 'rename-section'].includes(lower[configAt + 1] ?? '')
  if (sectionAction && args.slice(configAt + 1).some((a) => a.toLowerCase() === 'core' || mayBecome(a, 'core', fixed))) return REASON.hookBypass
  // 이름이 글자 그대로 core.hooksPath 가 아니어도 풀면 그것이 될 수 있으면 그 이름으로 본다(mayBecome — 값을 모르는 이름 `"$K"`도. 2026-10-15 R-168)
  let keyIndex = lower.indexOf('core.hookspath')
  if (keyIndex < 0) keyIndex = args.findIndex((a, k) => k > configAt && !a.startsWith('-') && mayBecome(a, 'core.hookspath', fixed))
  if (keyIndex < 0) return null
  if (lower.some((a) => a === 'unset' || a.startsWith('--unset'))) return REASON.hookBypass
  // 이름 바로 뒤의 낱말이 새 값이다 — git config는 이름 뒤의 낱말을 옵션으로 읽지 않는다(`git config core.hooksPath --get`도 값을 `--get`으로 바꾼다, git 2.54 실측).
  // 이름 앞에 조회(--get · --get-all · --get-regexp …, 하위 명령 get)가 있으면 뒤의 낱말은 값을 고르는 꼴이라 바꾸지 않는다.
  // 값을 받는 옵션(--comment · --file · -f · --blob · --type · --default · --value · --url)의 값은 조회가 아니다 — `git config --comment --get core.hooksPath /tmp/hooks`는
  // 주석이 "--get"인 바꾸기다(git 2.54 실측, 2026-10-13 4차 — 원칙 검토). 이름 앞의 낱말을 풀지 못하면(변수 · 명령 치환) --unset · --global 일 수 있어 막는다
  const before = lower.slice(configAt + 1, keyIndex)
  if (args.slice(configAt + 1, keyIndex).some((w) => unresolved(w, fixed))) return REASON.hooksPath
  let lookup = lower[configAt + 1] === 'get'
  for (let k = 0; k < before.length; k++) {
    if (!before[k].includes('=') && (GIT_CONFIG_VALUE_OPTIONS.has(before[k]) || /^-[a-z]*f$/.test(before[k]))) k++
    else if (before[k].startsWith('--get')) lookup = true
  }
  if (lookup) return null
  const value = args[keyIndex + 1]
  if (value === undefined) return appended ? REASON.hooksPath : null
  // 범위가 넓은 설정(--global · --system)과 다른 설정 파일(--file · -f · --blob)은 다른 저장소의 훅까지 바꾼다 — .githooks여도 막는다
  const widens = before.some((a) => /^--(global|system|file|blob)(=|$)/.test(a) || /^-[a-z]*f/.test(a))
  return widens || !PROJECT_HOOKS_PATH.test(value) ? REASON.hooksPath : null
}
/** git config 의 옵션 가운데 값을 다음 낱말로 받는 것(`--comment=…`처럼 = 로 붙이면 한 낱말) — -f 는 묶음의 끝에 와도 값을 받는다 */
const GIT_CONFIG_VALUE_OPTIONS = new Set(['--comment', '--file', '--blob', '--type', '--default', '--value', '--url'])

/**
 * 명령 줄 안에서 커밋 전 검사를 건너뛰거나 끄는가 — 까닭 또는 null. 셸이 다시 명령 줄로 읽는 글(nestedCommandLines: bash -c · eval · env -S ·
 * 셸이 받는 heredoc 본문 · here-string · 셸에 넘긴 echo · printf의 글)과 명령 치환(substitutionBodies) 속까지 본다. 깊이 제한은 git 판정(6, gitLineVerdict)과 같다.
 * 셸이 넘기는 인자 그대로 나눈 꼴(argvModes 의 merged — `git -C $(pwd) config …`, `git config core.hooksPath <<<.githooks /tmp/hooks`)도 본다 (2026-10-13 4차)
 */
function commitChecksBypassed(command, depth = 0) {
  if (depth > 3) return null
  for (const { segments, quotedBodies, merged } of argvModes(command)) {
    resolveShellVars(segments)
    const nested = nestedCommandLines(segments, bodyRunners(segments, '.'))
    for (const [i, segment] of segments.entries()) {
      const { words, cut } = segment
      const { name, args } = commandOf(words)
      const found = commitCheckBypass(words, name, args, cut, fixedWords(segment))
      if (found !== null) return found
      for (const { line } of nested[i]) {
        const inner = commitChecksBypassed(line, depth + 1)
        if (inner !== null) return inner
      }
    }
    // 치환의 몸은 나눈 꼴(merged 아님)에서 이미 본다
    if (merged) continue
    for (const body of substitutionBodies(segments, quotedBodies)) {
      const inner = commitChecksBypassed(body, depth + 1)
      if (inner !== null) return inner
    }
  }
  return null
}

/**
 * `git push`의 꼴 (2026-10-13 사용자 결정: 작업 가지 push는 묻지 않는다 — jarvis 가드 8번을 틀로 옮김, R-112. v35 2026-10-18: 강제는 막고 이름 없는 push 는 풀어 본다).
 * 옵션이 아닌 첫 낱말은 원격이고 그 뒤가 보낼 가지(refspec)다. 값을 받는 옵션(-o · --push-option · --repo · --receive-pack · --exec)의 값은
 * 원격 · 가지로 읽지 않는다(그렇게 읽으면 `git push -o ci.skip origin`이 가지를 적은 push로 보인다). 짧은 옵션은 묶어 쓸 수 있고(`-fu`, `-uo 값`),
 * 긴 옵션은 줄여 쓸 수 있다(`--forc`, `--del` — git이 받는다). 줄인 말이 위험한 옵션 하나라도 될 수 있으면 그것으로 본다(여럿과 맞으면 git이 거절할 뿐이다):
 * --force 가 될 수 있으면 강제(force — 막음), --force-with-lease · --force-if-includes 만 될 수 있으면 lease(작업 가지면 통과), --delete 면 지우기, 광역이면 bulk
 */
const PUSH_VALUE_OPTIONS = ['--push-option', '--repo', '--receive-pack', '--exec', '--recurse-submodules']
const PUSH_BULK_OPTIONS = ['--all', '--branches', '--mirror', '--prune', '--tags', '--follow-tags']
function pushShape(pushArgs) {
  const shape = { force: false, lease: false, del: false, bulk: false, positional: [] }
  for (let i = 0; i < pushArgs.length; i += 1) {
    const arg = pushArgs[i] ?? ''
    if (arg === '--') {
      shape.positional.push(...pushArgs.slice(i + 1))
      break
    }
    if (arg.startsWith('--')) {
      if (arg.startsWith('--no-')) continue
      const option = arg.split('=')[0]
      if (option.length > 2) {
        const may = (name) => name.startsWith(option)
        // --force 그 자체 · --force 까지 줄인 말(--forc · --for …) · 둘을 가르지 못하는 --force- 는 강제로 본다
        if (may('--force') || option === '--force-') shape.force = true
        else if (may('--force-with-lease') || may('--force-if-includes')) shape.lease = true
        if (may('--delete')) shape.del = true
        if (PUSH_BULK_OPTIONS.some(may)) shape.bulk = true
      }
      if (!arg.includes('=') && option.length > 3 && PUSH_VALUE_OPTIONS.some((o) => o.startsWith(option))) i += 1
    } else if (arg.startsWith('-') && arg.length > 1) {
      for (let j = 1; j < arg.length; j += 1) {
        if (arg[j] === 'f') shape.force = true
        if (arg[j] === 'd') shape.del = true
        if (arg[j] === 'o') {
          if (j === arg.length - 1) i += 1
          break
        }
      }
    } else {
      shape.positional.push(arg)
    }
  }
  return { ...shape, remote: shape.positional[0], refs: shape.positional.slice(1) }
}
/**
 * 원격의 기본 가지 — main · master와, 원격이 알려 준 것(`git symbolic-ref refs/remotes/<원격>/HEAD`, clone이 만든다).
 * 원격이 주소 · 경로이면 origin의 것을 본다. 파일 시스템 판정(fs)에서만 git을 부르고, 못 알면 main · master만 본다
 */
const defaultBranchCache = new Map()
function defaultBranches(dir, remote, fs) {
  const names = new Set(['main', 'master'])
  if (!fs || !dir) return names
  const name = remote !== undefined && /^[\w.-]+$/.test(remote) ? remote : 'origin'
  const key = `${dir}\0${name}`
  if (!defaultBranchCache.has(key)) {
    const r = spawnSync('git', ['-C', dir, 'symbolic-ref', '--quiet', '--short', `refs/remotes/${name}/HEAD`], { encoding: 'utf8', timeout: 3000 })
    const out = r.status === 0 ? (r.stdout ?? '').trim() : ''
    defaultBranchCache.set(key, out.startsWith(`${name}/`) ? out.slice(name.length + 1) : '')
  }
  const found = defaultBranchCache.get(key)
  if (found) names.add(found)
  return names
}
/** git의 전역 옵션 -C <폴더>를 따라간 작업 폴더 (`git -C a -C b`는 a/b) */
function gitWorkDir(args, dir) {
  let at = dir
  const end = gitSubcommandIndex(args)
  for (let i = 0; i < (end < 0 ? args.length : end); i++) {
    const arg = args[i] ?? ''
    if (arg === '-C') at = path.resolve(at ?? '.', expandHome(args[i + 1] ?? ''))
    if (GIT_GLOBAL_VALUE_OPTIONS.has(arg)) i++
  }
  return at
}
/** 저장소의 상태를 읽는 git(파일 시스템 판정에서만) — 출력(앞뒤 빈칸 뺌), 실패면 null. 같은 물음은 한 번만 */
const gitReadCache = new Map()
function gitRead(dir, ...args) {
  if (!dir) return null
  const key = JSON.stringify([dir, ...args])
  if (!gitReadCache.has(key)) {
    let out = null
    try {
      const r = spawnSync('git', ['-C', dir, ...args], { encoding: 'utf8', timeout: 3000 })
      out = r.status === 0 ? (r.stdout ?? '').trim() : null
    } catch {
      out = null
    }
    gitReadCache.set(key, out)
  }
  return gitReadCache.get(key)
}
/** 지금 가지 이름 — 분리된 HEAD 이거나 저장소가 아니면 null */
function currentBranch(dir) {
  const name = gitRead(dir, 'symbolic-ref', '--quiet', '--short', 'HEAD')
  return name ? name : null
}
/**
 * 이름 없는 push(`git push` · `git push origin` · `-u origin`)가 보낼 가지 — { branches: [지금 가지, @{push} 의 가지], remotes: [@{push} 의 원격] },
 * 풀지 못하면 null(물음): 분리된 HEAD, push.default=matching(같은 이름 가지를 모두 보냄), remote.<원격>.push 설정(보낼 곳을 바꿈), @{push} 를 풀지 못함
 * (upstream 이 없거나 simple 이 이름이 다른 upstream 을 거절). 지금 가지 이름도 늘 넣는다 — 원격을 적어 upstream 과 다른 곳으로 보내면 같은 이름으로 간다
 */
function unnamedPush(dir) {
  const branch = currentBranch(dir)
  if (branch === null) return null
  if (gitRead(dir, 'config', '--get', 'push.default') === 'matching') return null
  if (gitRead(dir, 'config', '--get-regexp', '^remote\\..*\\.push$')) return null
  const remote = gitRead(dir, 'for-each-ref', '--format=%(push:remotename)', `refs/heads/${branch}`)
  const ref = gitRead(dir, 'rev-parse', '--symbolic-full-name', '@{push}')
  if (!remote || !ref || !ref.startsWith(`refs/remotes/${remote}/`)) return null
  return { branches: [...new Set([branch, ref.slice(`refs/remotes/${remote}/`.length)])], remotes: [remote] }
}
/**
 * 2. 하위 명령 앞의 설정 덮어쓰기가 모두 gh 로그인 계정을 쓰는 표준 꼴인가 — `-c credential.helper=` · `-c credential.helper='!gh auth git-credential'`
 * (`credential.<주소>.helper` 도, gh 를 절대 경로로 준 것도). 다른 -c 키 · --config-env 는 보낼 곳을 바꿀 수 있어 묻는다(remote.origin.push=… 등)
 */
const CREDENTIAL_HELPER_KEY = /^credential(?:\..+)?\.helper$/i
const GH_CREDENTIAL_HELPER = /^!(?:gh|\/\S*\/gh) auth git-credential$/
function onlyCredentialOverrides(globalArgs) {
  for (let i = 0; i < globalArgs.length; i++) {
    const arg = globalArgs[i] ?? ''
    if (arg === '-c') {
      const pair = globalArgs[i + 1] ?? ''
      i++
      const eq = pair.indexOf('=')
      if (eq < 0 || !CREDENTIAL_HELPER_KEY.test(pair.slice(0, eq))) return false
      const value = pair.slice(eq + 1)
      if (value !== '' && !GH_CREDENTIAL_HELPER.test(value)) return false
      continue
    }
    if (/^-c/.test(arg) || /^--config-env/.test(arg)) return false
    if (GIT_GLOBAL_VALUE_OPTIONS.has(arg)) i++
  }
  return true
}
/**
 * 6. git push 의 판정 — null(통과) · 물음(REASON.push) · 막음(강제 · 기본 가지 강제 · 기본 가지 지우기). v35(2026-10-18):
 * ① 이름 없는 push 는 지금 가지 · @{push} 로 풀어 기본 가지가 아니면 통과(파일 시스템 판정에서만 — 글자만 볼 때는 모름) ② -c credential.helper 만 예외
 * ③ --force-with-lease · --force-if-includes 는 작업 가지면 통과, 기본 가지면 막음 ④ -f · --force · +가지는 막음(--force-with-lease 로 다시)
 * ⑤ 원격 가지 지우기는 같은 이름 로컬 가지가 있으면 통과 · 기본 가지는 막음 · 로컬 사본 없음과 태그는 물음.
 * refspec 은 받는 쪽으로 본다 — HEAD:main · x:main · :main 은 기본 가지로 가는 push 다(K3). forced: 같은 줄의 GIT_CONFIG_* 대입 · 입력에서 인자를 받는 명령이 돌림 — 늘 묻는다
 */
function pushVerdict(args, dir, fs, fixed = NO_WORDS, forced = false) {
  const at = gitSubcommandIndex(args)
  const shape = pushShape(args.slice(at + 1))
  const blocked = (reason) => ({ decision: 'deny', reason })
  // 강제는 보내는 곳과 상관없이 막는다 — 작업 가지는 --force-with-lease 가 남의 커밋을 지키며 같은 일을 한다
  if (shape.force || shape.refs.some((ref) => ref.startsWith('+'))) return blocked(REASON.pushForce)
  // 하위 명령 앞에서 설정을 덮어쓰면(-c remote.origin.push=… · --config-env) 이름을 적은 가지도 다른 곳으로 갈 수 있다 (2026-10-13 총괄 검토)
  // 원격을 풀지 못한 변수 · 명령 치환으로 주면 펼친 낱말이 가지까지 될 수 있다(`R="origin main"; git push $R`) — 묻는다 (2026-10-13 4차)
  let ask = forced || shape.bulk || (gitOverridesConfig(args) && !onlyCredentialOverrides(args.slice(0, at < 0 ? args.length : at))) || unresolved(shape.remote, fixed)
  const targets = [] // { name, del }
  const remotes = [shape.remote]
  if (shape.refs.length === 0) {
    const unnamed = !shape.del && fs ? unnamedPush(dir) : null
    if (unnamed === null) ask = true
    else {
      targets.push(...unnamed.branches.map((name) => ({ name, del: false })))
      remotes.push(...unnamed.remotes)
    }
  }
  for (const ref of shape.refs) {
    // 풀지 못한 변수 · 명령 치환으로 준 가지(`git push origin "$B"`), 와일드카드, 제외(^)는 보낼 곳을 모른다
    if (unresolved(ref, fixed) || ref.includes('*') || ref.startsWith('^')) {
      ask = true
      continue
    }
    const colon = ref.indexOf(':')
    const src = colon < 0 ? ref : ref.slice(0, colon)
    const dst = colon < 0 ? null : ref.slice(colon + 1)
    if (dst === '') {
      ask = true
      continue
    }
    const del = shape.del || (colon >= 0 && src === '')
    let name = dst ?? src
    if (name === 'HEAD' || name === '@') {
      // 지금 가지를 같은 이름으로 — 받는 쪽에 HEAD 를 쓴 꼴(x:HEAD)과 분리된 HEAD 는 모른다
      const branch = dst === null && fs ? currentBranch(dir) : null
      if (branch === null) {
        ask = true
        continue
      }
      name = branch
    }
    if (name.startsWith('refs/heads/')) name = name.slice('refs/heads/'.length)
    else if (name.startsWith('refs/')) {
      // 태그(refs/tags/ …)와 가지가 아닌 곳 — 보내기 · 지우기 모두 묻는다
      ask = true
      continue
    }
    targets.push({ name, del })
  }
  const defaults = new Set(remotes.flatMap((remote) => [...defaultBranches(dir, remote, fs)]))
  for (const { name, del } of targets) {
    const isDefault = defaults.has(name)
    if (del) {
      if (isDefault) return blocked(REASON.pushDeleteDefault)
      // 같은 이름 로컬 가지가 있으면 되돌릴 수 있다 — 없거나(태그일 수도) 모르면 묻는다
      if (!fs || gitRead(dir, 'rev-parse', '--verify', '--quiet', `refs/heads/${name}`) === null) ask = true
    } else if (isDefault) {
      if (shape.lease) return blocked(REASON.pushForce)
      ask = true
    }
  }
  return ask ? { decision: 'ask', reason: REASON.push } : null
}
/** 7. 기본 가지(main · master · 원격 HEAD)에 바로 커밋 — 카드 권한 없는 자리만 막는다(작업 가지로 안내). 지휘 · 단독은 통과(push 가 결정) */
function commitVerdict(dir, fs, ctx) {
  if (!fs || cardOf(ctx)) return null
  const branch = currentBranch(dir)
  return branch !== null && defaultBranches(dir, undefined, fs).has(branch) ? { decision: 'deny', reason: REASON.mainCommit } : null
}
/**
 * 6(새). git branch -D(--delete --force · -df) — 끝 커밋이 어떤 원격 가지에도 없으면(`git branch -r --contains`) 묻는다. 그 커밋은 reflog 가 지워지면 사라진다.
 * -d 는 git 이 병합 여부를 보니 그대로, -r(원격 추적 가지 지우기)도 그대로. 이름을 모르면(변수 · 입력에서 받음) 묻는다
 */
function branchVerdict(args, dir, fs, fixed = NO_WORDS, forced = false) {
  const rest = args.slice(gitSubcommandIndex(args) + 1)
  let del = false
  let force = false
  let remote = false
  const names = []
  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i] ?? ''
    if (arg === '--') {
      names.push(...rest.slice(i + 1))
      break
    }
    if (arg.startsWith('--')) {
      const option = arg.split('=')[0]
      if (option.length > 4 && '--delete'.startsWith(option)) del = true
      else if (option.length > 4 && '--force'.startsWith(option)) force = true
      else if (option.length > 4 && '--remotes'.startsWith(option)) remote = true
      continue
    }
    if (arg.startsWith('-') && arg.length > 1) {
      for (const c of arg.slice(1)) {
        if (c === 'D') del = force = true
        else if (c === 'd') del = true
        else if (c === 'f') force = true
        else if (c === 'r') remote = true
      }
      continue
    }
    names.push(arg)
  }
  if (!(del && force) || remote) return null
  const ask = { decision: 'ask', reason: REASON.branchDrop }
  if (forced || names.some((name) => unresolved(name, fixed))) return ask
  if (!fs) return null
  for (const name of names) {
    const tip = gitRead(dir, 'rev-parse', '--verify', '--quiet', `refs/heads/${name}^{commit}`)
    if (!tip) continue // 없는 가지 — git 이 거절한다
    if (!gitRead(dir, 'branch', '-r', '--contains', tip)) return ask
  }
  return null
}
/**
 * 8. 무시된 파일까지 지우기 — git clean 의 -x · -X(-fdx 처럼 묶어도), git stash -a · --all(push · save 포함). .gitignore 에 든 _core 와 .env 까지 지운다.
 * -e <패턴>(git clean)과 -m <글>(git stash)의 값 속 글자는 옵션이 아니다
 */
function cleanVerdict(args) {
  const at = gitSubcommandIndex(args)
  const sub = args[at]
  const rest = args.slice(at + 1)
  const blocked = { decision: 'deny', reason: REASON.cleanIgnored }
  if (sub === 'clean') {
    for (let i = 0; i < rest.length; i++) {
      const arg = rest[i] ?? ''
      if (arg === '--') break
      if (arg.startsWith('--')) {
        if (arg === '--exclude') i++
        continue
      }
      if (!/^-[A-Za-z]/.test(arg)) continue
      for (let k = 1; k < arg.length; k++) {
        if (arg[k] === 'x' || arg[k] === 'X') return blocked
        if (arg[k] === 'e') {
          if (k === arg.length - 1) i++
          break
        }
      }
    }
    return null
  }
  if (sub === 'stash') {
    const first = rest[0] ?? ''
    if (first !== '' && !first.startsWith('-') && first !== 'push' && first !== 'save') return null
    for (let i = first === 'push' || first === 'save' ? 1 : 0; i < rest.length; i++) {
      const arg = rest[i] ?? ''
      if (arg === '--') break
      if (arg.startsWith('--')) {
        const option = arg.split('=')[0]
        if (option.length > 2 && '--all'.startsWith(option)) return blocked
        if (!arg.includes('=') && ['--message', '--pathspec-from-file'].some((o) => option.length > 3 && o.startsWith(option))) i++
        continue
      }
      if (!/^-[A-Za-z]/.test(arg)) continue
      for (let k = 1; k < arg.length; k++) {
        if (arg[k] === 'a') return blocked
        if (arg[k] === 'm') {
          if (k === arg.length - 1) i++
          break
        }
      }
    }
  }
  return null
}
/** git 부르기 하나(args — 하위 명령 포함)의 판정: push · commit · branch · clean · stash. forced 는 push · branch 에만(보낼 곳 · 이름을 입력에서 받음) */
function gitCallVerdict(args, dir, fs, fixed, ctx, forced) {
  const work = gitWorkDir(args, dir)
  switch (gitSubcommand(args)) {
    case 'push':
      return pushVerdict(args, work, fs, fixed, forced)
    case 'commit':
      return commitVerdict(work, fs, ctx)
    case 'branch':
      return branchVerdict(args, work, fs, fixed, forced)
    case 'clean':
    case 'stash':
      return cleanVerdict(args)
    default:
      return null
  }
}
/** 둘 가운데 더 엄한 판정(같으면 앞의 것) */
function stricter(a, b) {
  const rank = (r) => (r?.decision === 'deny' ? 2 : r?.decision === 'ask' ? 1 : 0)
  return rank(b) > rank(a) ? b : a
}
/** 카드 권한 — 자리를 모르면(decide 를 seat 없이 부름) Paseo 밖처럼 있음. 자리를 주었으면 cardRight 가 true 일 때만 */
function cardOf(ctx) {
  return ctx?.seat ? ctx.seat.cardRight === true : true
}
/** git 설정을 환경 변수로 덮어쓰는 대입(GIT_CONFIG_COUNT · GIT_CONFIG_KEY_0 · GIT_CONFIG_PARAMETERS · GIT_CONFIG_GLOBAL …) — remote.<원격>.push로 보낼 곳을 바꿀 수 있다 */
const GIT_CONFIG_ASSIGNMENT = /^GIT_CONFIG\w*=/
/** 입력에서 인자를 받아 명령을 돌리는 것 — 그 git push가 어느 가지로 갈지 명령 줄만으로는 모른다 */
const PUSH_ARG_FEEDERS = new Set(['xargs', 'parallel', 'find', 'fd'])
/** 글만 내는 명령 — 인자의 git push는 명령이 아니다 */
const PUSH_TEXT_COMMANDS = new Set(['echo', 'printf', 'man'])
/**
 * 다른 명령이 돌리는 git — 인자에서 `git` 낱말을 찾아 그 뒤를 git의 인자로 본다(감싸는 명령을 하나씩 적지 않는다): timeout 60 git push …,
 * nice -n 5 git commit …, stdbuf -o0 git …, corepack pnpm exec git …, sudo -u 사용자 git …, xargs git …, find … -exec git … \;.
 * 글만 내는 명령(echo · printf · man)과 인자를 돌리지 않는 검색 · 읽기 명령(grep · rg · ag · cat … — runsNoArgs)의 인자는 명령이 아니다(`rg -n git commit --no-verify docs/`의
 * git 은 검색어다, 2026-10-13 4차). find · fd 의 -exec 명령은 `;`(또는 `{} +`)에서 끝난다 — 그 뒤는 git의 인자가 아니다(`find … -execdir git config core.hooksPath \;`는 조회다).
 * find · fd 낱말이 옵션의 값일 수 있으면(`env -u find git --namespace ';' push origin main` — -u 의 값) 끊지 않은 꼴도 본다(4dab3f51 은 물었다, 2026-10-13 4차).
 * [{ args, feeders(그 git 앞의 PUSH_ARG_FEEDERS) }] (2026-10-13 총괄 검토 · 총괄)
 */
function wrappedGitCalls(name, args) {
  if (name === 'git' || runsNoArgs(name)) return []
  const calls = []
  const chain = [name, ...args]
  args.forEach((arg, k) => {
    if (path.posix.basename(arg) !== 'git') return
    const before = chain.slice(0, k + 1)
    const feeders = before.map((w) => path.posix.basename(w)).filter((w) => PUSH_ARG_FEEDERS.has(w))
    const rest = args.slice(k + 1)
    const finders = before.flatMap((w, m) => (['find', 'fd'].includes(path.posix.basename(w)) ? [m] : []))
    const end = finders.length > 0 ? rest.findIndex((w, j) => w === ';' || (w === '+' && rest[j - 1] === '{}')) : -1
    if (end < 0) {
      calls.push({ args: rest, feeders })
      return
    }
    calls.push({ args: rest.slice(0, end), feeders })
    // 명령 이름이거나 옵션 뒤가 아닌 find · fd 는 분명히 find · fd 다 — 그때만 ; 에서 끊은 꼴 하나로 본다
    if (!finders.some((m) => m === 0 || !before[m - 1].startsWith('-'))) calls.push({ args: rest, feeders })
  })
  return calls
}
/** 인자를 명령으로 돌리지 않는 명령 — 글만 내는 것(echo · printf · man)과 검색 · 읽기만 하는 것(find 는 -exec 로 돌려 빼지 않는다) */
function runsNoArgs(name) {
  return PUSH_TEXT_COMMANDS.has(name) || ((READ_ONLY.has(name) || name === 'ag') && name !== 'find')
}
/**
 * 한 명령의 git 판정(6 — push · 가지 지우기 · 기본 가지 커밋 · 무시된 파일 지우기) — git 과 다른 명령이 돌리는 git(wrappedGitCalls). 셸이 다시 명령 줄로 읽는 글(bash -c '…')은
 * nestedCommandLines 가 본다. configEnv: 같은 명령 줄에서 앞서 git 설정 환경 변수를 정했거나 입력에서 인자를 받는 명령이 돌리는 명령 줄 속인가(그러면 어느 push든 묻는다).
 * 그 git 앞에 입력에서 인자를 받는 명령(xargs · find -exec …)이 있어도 push 는 묻고 가지 지우기는 이름을 모른다고 본다.
 * 이름을 풀지 못한 변수 · 명령 치환으로 준 명령(`$G push origin main`)은 git 일 수 있어 push 만 git 처럼 본다 (2026-10-13 4차)
 */
function commandGitVerdict(words, name, args, dir, fs, configEnv, fixed = NO_WORDS, ctx = {}) {
  const calls = []
  if (name === 'git') calls.push({ args, feeders: [] })
  else {
    if (unresolved(words[words.length - args.length - 1], fixed) && gitSubcommand(args) === 'push') calls.push({ args, feeders: [] })
    calls.push(...wrappedGitCalls(name, args))
  }
  const env = configEnv || words.some((w) => GIT_CONFIG_ASSIGNMENT.test(w))
  let worst = null
  for (const call of calls) {
    const fed = call.feeders.length > 0
    const forced = gitSubcommand(call.args) === 'push' ? env || fed : fed
    worst = stricter(worst, gitCallVerdict(call.args, dir, fs, fixed, ctx, forced))
  }
  return worst
}
/**
 * 셸을 부르는 인자 — { command(-c 의 명령 줄, 없으면 null), script(-c · -s 없이 스크립트 파일을 돌리는가 — 그러면 입력(heredoc · here-string · 파이프)은 명령 줄이 아니라 그 스크립트의 자료다) }.
 * 옵션은 첫 위치 인자 앞에만 온다. -c 는 묶음 어디에 있어도 되고(-ec · -ce · -lc) 명령 줄은 옵션 뒤의 첫 위치 인자다(`bash -c -e '…'`). 값을 받는 옵션
 * (-o · +o · -O · +O 이름 — `bash -euo pipefail -c '…'`, --rcfile · --init-file 파일)의 값은 건너뛴다. fish 는 --command · --init-command · -C 의 글도 명령 줄이다.
 * 예전에는 -c 앞의 옵션 값(pipefail)에서 찾기를 멈춰 명령 줄을 놓쳤다 (2026-10-13 4차 — 원칙 검토)
 */
function shellInvocation(name, args) {
  let c = false
  let s = false
  const lines = [] // -c 의 명령 줄과 fish 의 --command · --init-command · -C 글
  let i = 0
  for (; i < args.length; i++) {
    const arg = args[i] ?? ''
    if (arg === '--' || arg === '-') {
      i++
      break
    }
    if (arg.startsWith('--')) {
      const eq = arg.indexOf('=')
      const key = eq < 0 ? arg : arg.slice(0, eq)
      if (name === 'fish' && (key === '--command' || key === '--init-command')) lines.push(eq < 0 ? (args[++i] ?? '') : arg.slice(eq + 1))
      else if (eq < 0 && (key === '--rcfile' || key === '--init-file')) i++
      continue
    }
    if (!/^[-+][A-Za-z]/.test(arg)) break
    for (const flag of arg.slice(1)) {
      if (flag === 'c' && arg[0] === '-') c = true
      else if (flag === 's' && arg[0] === '-') s = true
      else if (flag === 'o' || flag === 'O') i++
      else if (flag === 'C' && name === 'fish') lines.push(args[++i] ?? '')
    }
  }
  if (c && args[i] !== undefined) lines.push(args[i])
  return { command: lines.length > 0 ? lines.join('\n') : null, script: !c && !s && lines.length === 0 && args[i] !== undefined }
}
/** 셸에 넘긴 명령 줄(bash -c '…', bash -lc '…', bash -euo pipefail -c '…', eval '…') — 없으면 null */
function shellInlineCommand(name, args) {
  if (name === 'eval') return args.join(' ')
  if (!SHELLS.has(name)) return null
  return shellInvocation(name, args).command
}
/** env의 값을 받는 짧은 옵션 — GNU env(-u · -C · -S · -a)와 BSD env(-u · -P · -S · -L · -U) */
const ENV_VALUE_OPTIONS = new Set(['u', 'C', 'S', 'a', 'P', 'L', 'U'])
/**
 * env -S '<명령 줄>' · -S'…' · -iS '…' · --split-string='…'(줄여 쓴 --split …도)의 글 — env가 낱말로 나눠 돌리는 명령이고, env 뒤에 남은 낱말은 그 뒤에 붙는다.
 * commandOf는 env를 감싸는 명령으로 건너뛰어 이름이 `-S`가 되므로 낱말에서 찾는다. env는 셸 문법(; · | · &&)을 풀지 않지만 셸에 넘긴 명령 줄처럼 넓게 본다.
 * [{ line, at(env 낱말의 차례) }]
 */
function envSplitLines(words) {
  const found = []
  words.forEach((word, at) => {
    if (path.posix.basename(word) !== 'env') return
    let split = null
    let i = at + 1
    while (split === null && (words[i] ?? '').startsWith('-')) {
      const option = words[i++]
      if (option === '--') break
      if (option.startsWith('--')) {
        const eq = option.indexOf('=')
        const key = eq < 0 ? option : option.slice(0, eq)
        const is = (long) => key.length > 2 && long.startsWith(key)
        if (is('--split-string')) split = eq < 0 ? (words[i++] ?? '') : option.slice(eq + 1)
        else if (eq < 0 && ['--unset', '--chdir', '--argv0'].some(is)) i++
        continue
      }
      for (let j = 1; j < option.length; j++) {
        if (!ENV_VALUE_OPTIONS.has(option[j])) continue
        const value = j + 1 < option.length ? option.slice(j + 1) : (words[i++] ?? '')
        if (option[j] === 'S') split = value
        break
      }
    }
    if (split === null) return
    const quote = (w) => `'${w.replaceAll("'", "'\\''")}'`
    found.push({ line: [split, ...words.slice(i).map(quote)].join(' '), at })
  })
  return found
}
/** 글 속 escape — echo -e · zsh · sh 의 echo와 printf가 푼다 */
const TEXT_ESCAPES = { n: '\n', t: '\t', r: '\r', v: '\v', f: '\f', a: '\x07', b: '\b', e: '\x1b', '\\': '\\' }
/**
 * echo · printf가 내는 글 — 셸이 받으면 명령 줄이 된다. echo는 -n · -e · -E를 떼고 인자를 띄어 잇고, printf는 형식의 %… 자리에 인자를 차례로 넣는다
 * (인자가 남으면 형식을 되풀이). escape(\n · \t · \xHH · \NNN)를 푼 글과 풀지 않은 글을 함께 낸다 — bash의 echo는 풀지 않고 zsh · sh의 echo와 printf는 푼다
 */
function printedTexts(name, args) {
  let text = ''
  if (name === 'echo') {
    let i = 0
    while (/^-[neE]+$/.test(args[i] ?? '')) i++
    text = args.slice(i).join(' ')
  } else {
    const [format = '', ...values] = args.slice(args[0] === '--' ? 1 : 0)
    let k = 0
    for (let round = 0; round < 64; round++) {
      let used = false
      text += format.replace(/%(?:%|[-+ #0']*(?:\d+|\*)?(?:\.(?:\d+|\*)?)?[A-Za-z])/g, (spec) => {
        if (spec === '%%') return '%'
        used = true
        return values[k++] ?? ''
      })
      if (!used || k >= values.length) break
    }
  }
  const unescaped = text.replace(/\\(x[0-9A-Fa-f]{1,2}|[0-7]{1,3}|.)/gs, (whole, e) =>
    /^x[0-9A-Fa-f]/.test(e) ? String.fromCharCode(parseInt(e.slice(1), 16)) : /^[0-7]/.test(e) ? String.fromCharCode(parseInt(e, 8)) : (TEXT_ESCAPES[e] ?? whole),
  )
  return unescaped === text ? [text] : [text, unescaped]
}
/**
 * 단순 명령이 돌리는 인터프리터와 그 뒤의 인자 — 이름이 인터프리터이거나(bash · node …), 다른 명령이 셸을 돌리면(timeout 5 bash · nice sh · sudo -u 사용자 bash ·
 * xargs sh) 그 셸. 셸은 인자에서 셸 낱말을 찾는다 — 감싸는 명령을 하나씩 적지 않는다(2026-10-13 총괄). 글만 내는 명령(echo · printf · man)과
 * 읽기만 하는 명령(grep -c bash · cat …, -exec 로 돌릴 수 있는 find 는 빼고)의 인자는 아니다. 없으면 null
 */
function interpreterOf(name, args) {
  if (INTERPRETERS.has(name)) return { runner: name, args }
  if (PUSH_TEXT_COMMANDS.has(name) || (READ_ONLY.has(name) && name !== 'find')) return null
  const k = args.findIndex((a) => SHELLS.has(path.posix.basename(a)))
  return k < 0 ? null : { runner: path.posix.basename(args[k]), args: args.slice(k + 1) }
}
/**
 * 단순 명령마다 그 heredoc 본문(과 here-string · echo · printf의 글)을 프로그램으로 실행하는 인터프리터(없으면 null) — 본문은 그것을 받는 명령이 실행할 때만 코드다:
 * 그 명령이 인터프리터이거나(bash <<'EOF', 다른 명령이 돌리는 셸 timeout 5 bash <<'EOF' — interpreterOf), 파이프로 인터프리터에 넘기거나(cat <<'EOF' | node),
 * 본문을 파일에 쓰고 같은 줄에서 그 파일을 실행할 때(cat > s.sh <<'EOF' … EOF; bash s.sh).
 * git commit -F - <<'EOF'의 본문은 메시지라, 같은 줄에 다른 bash가 있어도 코드로 보지 않는다
 * (2026-10-08 eyeson: 커밋 메시지 속 .env*.op 글자 때문에 명령 전체가 거부됨. 예전에는 줄에 인터프리터만 있으면 모든 본문을 봤다).
 * base: 상대 경로를 푸는 곳 — 같은 줄에서 쓰는 파일과 실행하는 파일을 견줄 때 쓴다
 */
function bodyRunners(segments, base) {
  const commands = segments.map(({ words }) => commandOf(words))
  const interpreters = commands.map(({ name, args }) => interpreterOf(name, args))
  const resolveFrom = (word) => path.resolve(base, expandHome(word))
  const runs = new Map() // 같은 줄에서 실행되는 파일 → 실행하는 프로그램('?'는 파일 자체를 실행)
  segments.forEach(({ words }, i) => {
    const { name, args } = commands[i]
    const run = name === 'source' || name === '.' ? { runner: 'bash', args } : interpreters[i]
    const file = run?.args.find((a) => !a.startsWith('-'))
    if (file !== undefined) runs.set(resolveFrom(file), run.runner)
    const command = words[words.length - args.length - 1] ?? ''
    if (command.includes('/')) runs.set(resolveFrom(command), '?')
  })
  return segments.map(({ outputs }, i) => {
    if (interpreters[i] !== null) return interpreters[i].runner
    for (let k = i; k < segments.length - 1 && segments[k].pipedOut; k++) {
      if (interpreters[k + 1] !== null) return interpreters[k + 1].runner
    }
    const written = commands[i].name === 'tee' ? [...outputs, ...commands[i].args.filter((a) => !a.startsWith('-'))] : outputs
    for (const file of written) {
      const runner = runs.get(resolveFrom(file))
      if (runner !== undefined) return runner
    }
    return null
  })
}
/**
 * 셸이 다시 명령 줄로 읽는 글 — 단순 명령마다 [{ line, fed }] (2026-10-13 총괄 — jarvis 비교 도구가 찾은 빈틈. 5 · 6번이 이 글을 명령 줄로 다시 판정한다):
 * 셸에 넘긴 명령 줄(bash -c · eval, 다른 명령이 돌리는 셸 timeout 5 bash -c · xargs sh -c · find … -exec sh -c 도), env -S의 글(envSplitLines),
 * 셸이 받는 heredoc 본문과 here-string(bash <<'EOF' · sh <<EOF · cat <<'EOF' | sh · bash <<< '…'), 셸에 넘긴 echo · printf의 글(echo '…' | bash).
 * 받는 셸은 bodyRunners(runners)로 가린다 — 파일에 쓰기만 하는 본문(cat <<'EOF' > notes.md)과 다른 명령의 글(git commit -F - <<'EOF')은 명령 줄이 아니다.
 * 셸이 스크립트 파일을 돌리면(`bash x.sh <<'EOF'`, `… | sh deploy.sh`) 받는 입력은 그 스크립트의 자료라 명령 줄이 아니다(scriptData, 2026-10-13 4차).
 * fed: 입력에서 인자를 받아 명령을 돌리는 것(PUSH_ARG_FEEDERS)이 그 셸 · env 앞에 있는가 — 그 안의 push는 어디로 갈지 몰라 늘 묻는다(6)
 */
function nestedCommandLines(segments, runners) {
  const fedBy = (before) => before.some((w) => PUSH_ARG_FEEDERS.has(path.posix.basename(w)))
  const data = scriptData(segments)
  return segments.map(({ words, heredocs, herestrings }, i) => {
    // 같은 줄에서 바로 실행하는 파일('?', cat > s.sh <<'EOF' … EOF; ./s.sh)은 셔뱅이 셸이거나 없으면 셸이 돈다
    const toShell = (text) => (SHELLS.has(runners[i] ?? '') && !data[i]) || (runners[i] === '?' && runByShell(text))
    const { name, args } = commandOf(words)
    if (PUSH_TEXT_COMMANDS.has(name)) {
      // 글만 내는 명령의 인자는 명령이 아니다 — 셸이 그 출력을 받을 때만 명령 줄이다(printf -v 는 변수에 담을 뿐 내지 않는다)
      const prints = name === 'echo' || (name === 'printf' && !/^-v/.test(args[0] ?? ''))
      return prints ? printedTexts(name, args).filter(toShell).map((line) => ({ line, fed: false })) : []
    }
    const lines = []
    const direct = shellInlineCommand(name, args)
    if (direct !== null) lines.push({ line: direct, fed: false })
    else if (!SHELLS.has(name) && name !== 'eval') {
      args.forEach((arg, k) => {
        const shell = path.posix.basename(arg)
        const line = SHELLS.has(shell) ? shellInlineCommand(shell, args.slice(k + 1)) : null
        if (line !== null) lines.push({ line, fed: fedBy([name, ...args.slice(0, k)]) })
      })
    }
    for (const { line, at } of envSplitLines(words)) lines.push({ line, fed: fedBy(words.slice(0, at)) })
    for (const text of [...heredocs, ...herestrings]) if (toShell(text)) lines.push({ line: text, fed: false })
    return lines
  })
}
/**
 * 단순 명령마다 그 heredoc 본문 · here-string · 파이프로 넘긴 글을 받는 셸이 스크립트 파일을 돌리는가(bodyRunners 와 같은 셸 — 그 명령이거나 파이프로 받는 것).
 * 그러면 입력은 스크립트가 읽는 자료다 — 5 · 6번은 명령 줄로 보지 않는다(`bash x.sh <<'EOF'⏎git push origin main 은 묻는다⏎EOF`가 묻던 것, 2026-10-13 4차).
 * 1 · 3번은 그 스크립트가 무엇을 읽을지 몰라 예전처럼 본문을 본다. -c 로 명령 줄을 준 셸의 입력은 그 명령이 다시 셸에 넘길 수 있어 예전처럼 명령 줄로 본다
 */
function scriptData(segments) {
  const runs = segments.map(({ words }) => {
    const { name, args } = commandOf(words)
    return interpreterOf(name, args)
  })
  return segments.map((_, i) => {
    let run = runs[i]
    for (let k = i; run === null && k < segments.length - 1 && segments[k].pipedOut; k++) run = runs[k + 1]
    return run !== null && SHELLS.has(run.runner) && shellInvocation(run.runner, run.args).script
  })
}
/** 스크립트를 셸이 돌리는가 — 셔뱅(#!)이 셸(bash · sh · zsh, env 뒤 포함)이거나 없을 때(셸이 셔뱅 없는 실행 파일을 스스로 돌린다) */
function runByShell(text) {
  const m = /^#!\s*(\S+)(?:[ \t]+(\S+))?/.exec(text)
  if (m === null) return true
  const program = path.posix.basename(m[1]) === 'env' ? (m[2] ?? '') : m[1]
  return SHELLS.has(path.posix.basename(program))
}
/**
 * 명령 줄을 나눈 꼴들 — 늘 푼 꼴(ansiC)로 나누고, 거기서 $'…' · $"…"를 풀었으면 두 가지 모두 보고 더 엄한 쪽을 따른다: 푼 꼴(bash · zsh · ksh 는 $'…'를 풀고 bash · ksh 는 $"…"를 "…"로 읽는다)과
 * 예전처럼 $ 를 글자로 둔 꼴(dash · Debian의 sh 는 $'…'를 풀지 않고, zsh 는 $"…"의 $ 를 남긴다 — `$'\'⏎git commit …⏎'`은 dash 에서 둘째 줄이 돈다).
 * 셸에 넘긴 글(sh -c · dash <<'EOF' …)도 그 글마다 다시 고른다 (2026-10-13 총괄 — jarvis 비교 도구 2차)
 */
function splitModes(command) {
  const decodedSplit = { ...splitCommands(command, true), ansiC: true }
  return decodedSplit.decoded ? [decodedSplit, { ...splitCommands(command, false), ansiC: false }] : [decodedSplit]
}
/**
 * 5 · 6번이 보는 꼴 — splitModes 의 꼴마다, 셸이 명령에 넘기는 인자가 나눈 낱말과 다를 수 있으면(argvDiffers — 따옴표 밖의 명령 치환 · 입력 리디렉션 · here-string)
 * 인자 그대로 나눈 꼴(merged: 치환 자리에 SUBSTITUTED, 치환 뒤의 낱말도 그 명령의 것, 리디렉션 대상은 뺌)도 본다. 나눈 꼴의 판정은 그대로 두고 더 엄한 쪽을 따른다
 * (`git -C $(pwd) config --unset core.hooksPath`의 나눈 꼴은 이름이 config 인 명령이 따로 나왔다, 2026-10-13 4차 — 원칙 검토)
 */
function argvModes(command) {
  return splitModes(command).flatMap((split) => (split.argvDiffers ? [split, { ...splitCommands(command, split.ansiC, true), ansiC: split.ansiC, merged: true }] : [split]))
}
/** 셸이 펼쳐 실행하는 명령 치환의 몸 — 큰따옴표 안의 $(…) · `…`(quotedBodies — 따옴표 밖은 splitCommands가 이미 나눈다)와 따옴표 없는 heredoc(<<EOF) 본문의 것 */
function substitutionBodies(segments, quotedBodies) {
  return [...quotedBodies, ...segments.flatMap(({ expandingHeredocs }) => expandingHeredocs.flatMap((body) => heredocSubstitutions(body)))]
}
/**
 * 명령 줄 안의 git 판정(6 — 셸이 다시 명령 줄로 읽는 글 · 명령 치환 속까지) — 가장 엄한 것(막음이 나오면 바로 끝).
 * fed: 입력에서 인자를 받는 명령(xargs · find -exec …)이 돌리는 명령 줄인가 — 그 안의 push는 늘 묻는다.
 * 셸이 넘기는 인자 그대로 나눈 꼴(argvModes 의 merged — `git -C $(pwd) push origin main`)도 본다 (2026-10-13 4차)
 */
function gitLineVerdict(command, dir, fs, depth = 0, fed = false, ctx = {}) {
  if (depth > 3) return null
  let worst = null
  for (const { segments, quotedBodies, merged } of argvModes(command)) {
    resolveShellVars(segments)
    const nested = nestedCommandLines(segments, bodyRunners(segments, dir ?? '.'))
    let at = dir
    let configEnv = fed
    for (const [i, segment] of segments.entries()) {
      const { words } = segment
      const { name, args } = commandOf(words)
      if (name === 'cd' || name === 'pushd') {
        const target = args.find((a) => !a.startsWith('-'))
        at = target === undefined ? HOME || at : path.resolve(at ?? '.', expandHome(target))
      }
      if (words.some((w) => GIT_CONFIG_ASSIGNMENT.test(w))) configEnv = true
      worst = stricter(worst, commandGitVerdict(words, name, args, at, fs, configEnv, fixedWords(segment), ctx))
      for (const inner of nested[i]) worst = stricter(worst, gitLineVerdict(inner.line, at, fs, depth + 1, fed || inner.fed, ctx))
      if (worst?.decision === 'deny') return worst
    }
    // 치환의 몸은 나눈 꼴(merged 아님)에서 이미 본다
    if (!merged) for (const inner of substitutionBodies(segments, quotedBodies)) worst = stricter(worst, gitLineVerdict(inner, dir, fs, depth + 1, fed, ctx))
    if (worst?.decision === 'deny') return worst
  }
  return worst
}

/** 1Password CLI의 하위 명령 — `op [전역 옵션] read …`, `op item get …` */
const OP_SUBCOMMANDS = new Set([
  'read', 'inject', 'run', 'item', 'document', 'vault', 'account', 'service-account', 'whoami', 'signin',
  'signout', 'user', 'group', 'connect', 'events-api', 'plugin', 'completion', 'update', 'environment',
])
function opCommand(args) {
  const index = args.findIndex((arg) => OP_SUBCOMMANDS.has(arg))
  if (index === -1) return ''
  const first = args[index]
  if (first !== 'item' && first !== 'document') return first
  const second = args.slice(index + 1).find((arg) => !arg.startsWith('-')) ?? ''
  return `${first} ${second}`
}

/**
 * op가 값을 어디로 내는가 — 'stdout'(화면), 'file'(파일), null(값을 내지 않음).
 * op run은 출력에 찍힌 값을 가리므로 null이다. 화면으로 내는 명령은 다른 명령에 파이프로 넘길 때만 허용한다.
 * 항목을 출력하는 명령(item get, 만든·고친 항목이나 --dry-run 미리보기를 내는 item create·edit)은 --reveal이나
 * JSON 출력(--format json, 명령 앞의 OP_FORMAT=json)일 때 비밀 칸의 값이 그대로 나온다.
 * jsonByEnv: 명령 앞에 OP_FORMAT=json이 붙었는가
 */
function opRevealsValue(args, jsonByEnv = false) {
  const command = opCommand(args)
  const toFile = args.some((arg) => arg === '-o' || arg.startsWith('--out-file'))
  if (command === 'read' || command === 'inject' || command === 'document get') return toFile ? 'file' : 'stdout'
  if (command === 'item get' || command === 'item create' || command === 'item edit') {
    const json = jsonByEnv || args.some((arg, i) => arg === '--format=json' || (arg === '--format' && args[i + 1] === 'json'))
    const reveals =
      json || args.some((arg) => ['--reveal', '--otp'].includes(arg) || (command === 'item get' && arg.startsWith('--fields')))
    return reveals ? 'stdout' : null
  }
  return null
}

/** op item create·edit의 인자로 비밀 칸 값을 넘기는가 — `칸[password]=값`, `칸[concealed]=값`, Login의 `password=값` */
function opPassesSecretArg(args) {
  const command = opCommand(args)
  if (command !== 'item create' && command !== 'item edit') return false
  return args.some((arg) => /^(password|[^=]*\[(password|concealed)\])=./.test(arg))
}

/** security가 키체인의 비밀값을 출력하는가 — find-*-password의 -w·-g, dump-keychain. -w 없는 존재 확인은 괜찮다 */
function revealsKeychainSecret(args) {
  const sub = args.find((arg) => !arg.startsWith('-')) ?? ''
  if (sub === 'dump-keychain') return true
  if (!/^find-(generic|internet)-password$/.test(sub)) return false
  return args.some((arg) => /^-[A-Za-z]*[wg][A-Za-z]*$/.test(arg))
}

const EXISTENCE_ONLY = new Set(['ls', 'test', '[', '[[', 'stat'])
// v35(9, 2026-10-18): 내용을 보기만 하는 명령을 더한다 — _core 읽기 물음이 잦았다(팀원은 물음이 막힘이 된다). bat 은 --pager 로 다른 프로그램을 돌릴 수 있어
// 그때는 읽기가 아니다(readsOnly). sort 의 -o · --output 은 그 파일에 쓴다(sortOutputs — 쓰는 곳으로 본다)
const READ_ONLY = new Set([
  'cat', 'less', 'more', 'head', 'tail', 'grep', 'egrep', 'fgrep', 'rg', 'ls', 'find', 'wc',
  'file', 'stat', 'diff', 'tree', 'du', 'sed', 'sort', 'uniq', 'cut', 'jq', 'realpath',
  'readlink', 'basename', 'dirname', 'test', '[', 'echo', 'printf', 'cd', 'pwd',
  'nl', 'tac', 'rev', 'column', 'tr', 'paste', 'fold', 'comm', 'join', 'expand', 'unexpand',
  'shasum', 'md5', 'cksum', 'strings', 'od', 'look', 'fmt', 'bat',
])

/** 읽기만 하는 명령 — 내용을 바꾸거나 새 파일을 만들지 않는다 (sed -i, find -delete·-exec, sort -o, bat --pager는 아님) */
function readsOnly(name, args) {
  if (name === 'sed') return !args.some((arg) => /^-[A-Za-z]*i/.test(arg) || arg.startsWith('--in-place'))
  if (name === 'find') return !args.some((arg) => /^-(delete|exec|execdir|ok|okdir|fprint)/.test(arg))
  if (name === 'sort') return sortOutputs(args).length === 0
  if (name === 'bat') return !args.some((arg) => /^--pager/.test(arg))
  return READ_ONLY.has(name)
}

/**
 * sort 가 결과를 쓰는 파일 — -o <파일> · -o<파일>(묶음 속 o 뒤) · --output <파일> · --output=<파일>(줄인 --o … 도). 값을 받는 다른 짧은 옵션(-k · -t · -S · -T)의 값은 아니다
 */
function sortOutputs(args) {
  const found = []
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] ?? ''
    if (arg === '--') break
    if (arg.startsWith('--')) {
      const eq = arg.indexOf('=')
      const option = eq < 0 ? arg : arg.slice(0, eq)
      if (option.length > 2 && '--output'.startsWith(option)) {
        found.push(eq < 0 ? (args[i + 1] ?? '') : arg.slice(eq + 1))
        if (eq < 0) i++
      } else if (eq < 0 && ['--key', '--field-separator', '--buffer-size', '--temporary-directory', '--parallel', '--files0-from', '--compress-program', '--random-source', '--batch-size', '--sort'].includes(option)) i++
      continue
    }
    if (!/^-[A-Za-z]/.test(arg)) continue
    for (let k = 1; k < arg.length; k++) {
      const c = arg[k]
      if (c === 'o') {
        found.push(k < arg.length - 1 ? arg.slice(k + 1) : (args[i + 1] ?? ''))
        if (k === arg.length - 1) i++
        break
      }
      if ('ktST'.includes(c)) {
        if (k === arg.length - 1) i++
        break
      }
    }
  }
  return found.filter((file) => file !== '')
}

/** 참조 파일을 읽기만 하는 명령 — 읽기만 하는 명령, git, 값을 파일로 내지 않는 op run·inject */
function readsReferenceOnly(name, args) {
  if (readsOnly(name, args) || name === 'git') return true
  if (name === 'op') {
    const command = opCommand(args)
    return command === 'run' || (command === 'inject' && opRevealsValue(args) !== 'file')
  }
  return false
}

/**
 * grep/rg의 패턴 인자 가운데 비밀값 참조로 보지 않는 것 — .env를 빼라는 패턴과, 1Password 참조 파일(*.op)만 고르는 패턴
 */
function isEnvExclusion(word, previous) {
  if (/^--exclude(-dir)?=/.test(word)) return true
  if (/^--include=.*\.op$/.test(word) || (previous === '--include' && word.endsWith('.op'))) return true
  if (/^(-g|--glob|--iglob)=?!/.test(word)) return true
  return (previous === '-g' || previous === '--glob' || previous === '--iglob') && word.startsWith('!')
}

/**
 * 빼는 패턴이 .env 를 대소문자 모두로 덮는가 — grep --exclude · rg -g/--glob 은 대소문자를 가려, 소문자 .env 만 빼면 .ENV.local 은 빠지지 않고 읽힌다
 * (macOS 기본 APFS, 2026-10-17 R-235). rg --iglob(caseless)은 .env 를 어떤 대소문자로 써도 되고, 그 밖에는 [eE][nN][vV] 처럼 글자마다 두 꼴을 다 담은
 * 글자 묶음일 때만 인정한다(부정 묶음 [!…] · [^…] 은 아님)
 */
const ENV_ANY_CASE_CLASS = /\.\[(?![!^])(?=[^\]]*e)(?=[^\]]*E)[^\]]*\]\[(?![!^])(?=[^\]]*n)(?=[^\]]*N)[^\]]*\]\[(?![!^])(?=[^\]]*v)(?=[^\]]*V)[^\]]*\]/
function excludesEnvAnyCase(pattern, caseless) {
  return (caseless && /\.env/i.test(pattern)) || ENV_ANY_CASE_CLASS.test(pattern)
}

/** rg 의 인자가 .env 를 대소문자 모두로 빼는 패턴인가 — -g · --glob '!…'(대소문자를 가림) · --iglob '!…'(가리지 않음) */
function rgExcludesEnv(arg, previous) {
  const joined = /^(-g|--glob|--iglob)=?(!.*)$/.exec(arg)
  if (joined) return excludesEnvAnyCase(joined[2], joined[1] === '--iglob')
  if (['-g', '--glob', '--iglob'].includes(previous) && arg.startsWith('!')) return excludesEnvAnyCase(arg, previous === '--iglob')
  return false
}

/** grep --include가 1Password 참조 파일(*.op)만 고르는가 — 키 교체 때 참조를 찾는 검색은 값을 읽지 않는다 */
function includesOnlyReferenceFiles(args) {
  const patterns = includePatterns(args)
  return patterns.length > 0 && patterns.every((pattern) => pattern.endsWith('.op'))
}

/** grep의 --include 패턴들 (--include=<글롭> 과 --include <글롭> 두 꼴) */
function includePatterns(args) {
  return args.flatMap((arg, i) =>
    arg.startsWith('--include=') ? [arg.slice('--include='.length)] : args[i - 1] === '--include' ? [arg] : [],
  )
}

/**
 * .env 꼴 파일 이름 — --include가 이 가운데 하나라도 고를 수 있으면 .env를 읽을 수 있다고 본다.
 * 환경 이름(.env.prod, .env.vercel 등)과 그 .local, 백업 꼬리(.env.bak, .env.local~ 등)를 겹쳐 만든다
 * (2026-10-11 설정 적용 세션이 --include='*.prod'·'*.bak' 빈틈을 찾음). 코드·자료 확장자(*.ts, *.json, *.yaml)는
 * 일부러 넣지 않는다 — 코드 검색이 다시 막히기 때문이다. 그래서 .env.json·.env.yaml 같은 평문 파일은 이 검사로 막지 못한다
 * (2026-10-11 프로젝트 폴더에는 없음)
 */
const ENV_WORDS = ['local', 'development', 'dev', 'production', 'prod', 'test', 'testing', 'staging', 'stage', 'preview', 'ci', 'qa', 'uat', 'e2e', 'sandbox', 'demo', 'vercel', 'fly', 'sample', 'template']
const BACKUP_TAILS = ['bak', 'backup', 'old', 'orig', 'save', 'tmp', 'copy', 'swp']
const ENV_STEMS = ['.env', ...ENV_WORDS.map((w) => `.env.${w}`), ...ENV_WORDS.filter((w) => w !== 'local').map((w) => `.env.${w}.local`)]
const ENV_LIKE_NAMES = [
  ...ENV_STEMS,
  ...ENV_STEMS.flatMap((stem) => [...BACKUP_TAILS.map((tail) => `${stem}.${tail}`), `${stem}~`]),
  '.envrc', '.env.keys', '.env.me', '.env.vault',
]

/** grep --include의 글롭(*, ?, [..])을 정규식으로. 맨 앞 점도 *가 고른다고 보아, 대소문자도 가리지 않고(R-226) 넓게(막는 쪽으로) 맞춘다 */
function globToRegExp(glob) {
  let out = ''
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]
    if (c === '*') out += '.*'
    else if (c === '?') out += '.'
    else if (c === '[') {
      const end = glob.indexOf(']', i + 1)
      if (end > i) {
        out += `[${glob.slice(i + 1, end).replace(/^!/, '^').replace(/\\/g, '\\\\')}]`
        i = end
      } else out += '\\['
    } else out += c.replace(/[.+^${}()|\\\]\/]/g, '\\$&')
  }
  return new RegExp(`^${out}$`, 'i')
}

/**
 * grep --include가 모두 .env 꼴 파일과 맞지 않는가 — 코드 파일만 고르는 재귀 검색(--include='*.ts' 등)은 .env를 읽지 않는다
 * (2026-10-11 apahere 팀 지휘의 코드 검색이 막힘, 사용자 결정으로 허용)
 */
function includesNoEnvFiles(args) {
  const patterns = includePatterns(args)
  return patterns.length > 0 && patterns.every((pattern) => {
    const re = globToRegExp(pattern)
    return !ENV_LIKE_NAMES.some((name) => re.test(name))
  })
}

/** 패턴을 스스로 푸는 옵션 — 셸이 아니라 그 프로그램이 펼치므로 따옴표 안이어도 글롭이다 */
const SELF_GLOB_OPTIONS = new Map([
  ['find', new Set(['-name', '-iname', '-path', '-ipath', '-wholename', '-iwholename'])],
  ['rg', new Set(['-g', '--glob', '--iglob'])],
])

/**
 * find -name '.env*' -exec cat {} +, rg -g '.env*'처럼 프로그램이 직접 펼칠 패턴들.
 * 빼는 패턴(find -not -name …, find ! -name …, rg -g '!…')은 .env를 고르지 않으므로 넣지 않는다
 */
function selfGlobPatterns(name, args) {
  const options = SELF_GLOB_OPTIONS.get(name)
  if (!options) return []
  const patterns = []
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] ?? ''
    const eq = arg.indexOf('=')
    if (eq > 0 && options.has(arg.slice(0, eq))) patterns.push(arg.slice(eq + 1))
    else if (options.has(arg) && i + 1 < args.length) {
      const negated = ['-not', '!'].includes(args[i - 1] ?? '')
      i++
      if (!negated) patterns.push(args[i] ?? '')
    }
  }
  return patterns.filter((pattern) => !pattern.startsWith('!'))
}

/**
 * fs: 기획 자료 판정(3)까지 하는가 — 그 판정은 파일 시스템(공유 드라이브)을 본다. false면 글자만 보는 판정(1, 2, 4, 5)만 한다
 * captured: 명령 치환의 몸인가(큰따옴표 안 · 따옴표 없는 heredoc 본문의 $(…) · `…`) — 그 출력은 바깥 명령의 인자가 된다(1의 echo · printf)
 * $'…' · $"…"를 푼 명령 줄은 두 꼴로 나눠 보고(splitModes) 더 엄한 판정을 낸다 — 같으면 푼 꼴(먼저 본 것)의 까닭을 둔다.
 * 셸이 넘기는 인자가 나눈 낱말과 다를 수 있으면(argvDiffers — 따옴표 밖의 명령 치환 · 입력 리디렉션 · here-string) 인자 그대로 나눈 꼴로 5 · 6번을 더 본다
 * (checkArgvAs — `git -C $(pwd) config --unset core.hooksPath`, 2026-10-13 4차).
 * 같은 글은 한 번만 판정한다(checkBashMemo) — 치환 속 글을 두 꼴이 겹쳐 볼 때 깊이마다 일이 두 배가 되지 않게
 */
const checkBashMemo = new Map()
function checkBash(command, ctx, fs = true, captured = false) {
  // 자리의 카드 권한도 열쇠에 — 7 · 13번 판정이 그것으로 갈린다
  const key = JSON.stringify([command, ctx.root, ctx.cwd ?? null, fs, captured, cardOf(ctx)])
  if (checkBashMemo.has(key)) return checkBashMemo.get(key)
  let worst = null
  const take = (result) => {
    if (result !== null && (worst === null || (result.decision === 'deny' && worst.decision !== 'deny'))) worst = result
  }
  for (const split of splitModes(command)) {
    take(checkBashAs(split, ctx, fs, captured))
    if (split.argvDiffers) take(checkArgvAs(splitCommands(command, split.ansiC, true), ctx, fs))
  }
  checkBashMemo.set(key, worst)
  return worst
}
/**
 * 셸이 넘기는 인자 그대로 나눈 꼴(splitCommands 의 merge)에서 5 · 6번만 본다 — 나눈 꼴의 판정(checkBashAs)에 더해 더 엄한 쪽을 따른다.
 * 치환의 몸은 나눈 꼴에서 이미 보므로 다시 보지 않는다 (2026-10-13 4차)
 */
function checkArgvAs({ segments }, ctx, fs) {
  let found = null
  resolveShellVars(segments)
  const nested = nestedCommandLines(segments, bodyRunners(segments, ctx.cwd ?? ctx.root))
  let dir = ctx.cwd
  let configEnv = false
  for (const [index, segment] of segments.entries()) {
    const { words } = segment
    const { name, args } = commandOf(words)
    if (name === 'cd' || name === 'pushd') {
      const target = args.find((a) => !a.startsWith('-'))
      dir = target === undefined ? HOME || dir : path.resolve(dir ?? ctx.root, expandHome(target))
    }
    const fixed = fixedWords(segment)
    const bypass = commitCheckBypass(words, name, args, null, fixed)
    if (bypass !== null) return { decision: 'deny', reason: bypass }
    for (const { line } of nested[index]) {
      const inner = commitChecksBypassed(line)
      if (inner !== null) return { decision: 'deny', reason: inner }
    }
    if (words.some((w) => GIT_CONFIG_ASSIGNMENT.test(w))) configEnv = true
    const at = dir ?? ctx.root
    found = stricter(found, commandGitVerdict(words, name, args, at, fs, configEnv, fixed, ctx))
    for (const { line, fed } of nested[index]) found = stricter(found, gitLineVerdict(line, at, fs, 0, fed, ctx))
    if (found?.decision === 'deny') return found
  }
  return found
}
/** checkBash의 한 꼴 — split: splitModes가 나눈 것({ segments, quotedBodies: 큰따옴표 안의 명령 치환의 몸 }) */
function checkBashAs({ segments, quotedBodies }, ctx, fs, captured) {
  let decision = null
  const escalate = (next) => {
    // deny가 ask보다 우선한다
    if (next.decision === 'deny' || decision === null) decision = next
  }

  resolveShellVars(segments)
  // 같은 명령 줄에서 perl 이 읽는 환경 변수(PERL5OPT · PERL5LIB · PERL5DB …)를 정하거나, 이름을 모르는 변수를 내보내면(export "$N"=… · set -a)
  // perl 한 줄 프로그램을 읽기만 한다고 보지 않는다 — -M · -d 를 몰래 넣을 수 있다 (2026-10-15 R-168)
  const perlEnvTouched = segments.some(({ words }) => {
    const { name, args } = commandOf(words)
    if (words.some((w) => /PERL|allexport/.test(w))) return true
    if (name === 'set') return args.some((a) => /^[-+][A-Za-z]*a/.test(a))
    return (DECLARERS.has(name) || words[0] === 'env') && words.some((w) => unresolved(w))
  })

  // 큰따옴표 안의 명령 치환도 실행되는 명령이다 — 그 안에서 값이 나오면 출력은 변수로 잡힌다(파이프가 아니다).
  // heredoc 본문은 명령 줄이 아니라서 뺀다 — 따옴표 친 heredoc(<<'EOF') 본문의 "…`.env`…"는 실행되지 않는 글이다
  for (const inner of quotedBodies) {
    const result = checkBash(inner, ctx, fs, true)
    if (result) escalate(result)
  }
  // 따옴표 없는 heredoc(<<EOF) 본문의 $(…)·`…`는 셸이 펼쳐 실행한다 (cat <<EOF 안의 $(cat .env.local)도 값을 읽는다)
  for (const { expandingHeredocs } of segments) {
    for (const body of expandingHeredocs) {
      for (const inner of heredocSubstitutions(body)) {
        const result = checkBash(inner, ctx, fs, true)
        if (result) escalate(result.reason.includes(REASON.heredocQuote) ? result : { ...result, reason: result.reason + REASON.heredocQuote })
      }
    }
  }

  // heredoc 본문을 실행하는 프로그램(없으면 null) — 그것을 받는 명령이 실행할 때만 코드다(bodyRunners: bash <<'EOF', cat <<'EOF' | node,
  // cat > s.sh <<'EOF' … EOF; bash s.sh). git commit -F - <<'EOF'의 본문은 메시지다 (2026-10-08 eyeson)
  const bodyRunner = bodyRunners(segments, ctx.cwd ?? ctx.root)
  // 셸이 다시 명령 줄로 읽는 글(bash -c · eval · env -S · 셸이 받는 heredoc 본문 · here-string · 셸에 넘긴 echo · printf의 글) — 5 · 6번이 본다
  const nested = nestedCommandLines(segments, bodyRunner)
  // 기획 자료를 가리키는 명령의 출력을 파이프로 받는가, 그 목록을 받은 while read 반복문 안인가 (3-2)
  let pipeFromPrivate = false
  let loopFromPrivate = false
  // for 머리의 목록이 명령 치환($(…)·`…`)이면 그 안의 명령은 머리와 do 사이의 따로 된 명령으로 나온다 — 그것이 기획 자료를 가리키면 목록도 기획 자료다
  let loopListPending = false
  // 같은 명령 줄에서 git이 읽는 환경 변수를 정했는가 — `GIT_PAGER=… git log`(앞머리는 commandOf가 건너뛰어 args에 없다), env, export
  let gitEnv = false
  // 그 가운데 git 설정을 덮어쓰는 것(GIT_CONFIG_*)을 정했는가 — push가 보낼 곳을 바꿀 수 있다 (6)
  let gitConfigEnv = false

  // 같은 명령 줄의 cd·pushd를 따라간다. 시작은 입력의 cwd다 — 앞선 명령의 `cd _private`가 작업 폴더로 이어져 들어온다.
  // `cd -`·popd처럼 어디로 가는지 모르면 그대로 둔다
  let dir = ctx.cwd
  // 묶음({ … } · 반복문 · 조건문)의 출력을 파이프나 > 로 보내는가 — 그 안의 echo · printf 도 홀로 쓴 것이 아니다
  const groupRedirected = segments.some(({ words, pipedOut, outputs }) => ['}', 'done', 'fi', 'esac'].includes(words[0]) && (pipedOut || outputs.length > 0))
  const groupPiped = segments.some(({ words, pipedOut }) => ['}', 'done', 'fi', 'esac'].includes(words[0]) && pipedOut)
  // 비밀값 판정(1)은 묶음의 출력이 프로세스 치환이나 치환 뒤의 파이프로 가는 것(feedsCommand)도 본다
  const groupFeeds = segments.some(({ words, pipedOut, feedsCommand }) => ['}', 'done', 'fi', 'esac'].includes(words[0]) && (pipedOut || feedsCommand))
  for (const [index, { words, globs, outputs, heredocs, pipedOut, feedsCommand, assignOnly, inParen, cut }] of segments.entries()) {
    const { name, args, program } = commandOf(words)
    // 대입만 있는 명령(`PAGER=…; git log`)도 본다 — 이미 내보낸 변수면 뒤의 git이 그 값을 받는다
    if (words.some((w) => GIT_ENV_ASSIGNMENT.test(w))) gitEnv = true
    const changesDir = name === 'cd' || name === 'pushd' || name === 'popd'
    if (name === 'cd' || name === 'pushd') {
      const target = args.find((a) => !a.startsWith('-'))
      if (target === undefined) dir = HOME || dir
      else dir = path.resolve(dir ?? ctx.root, expandHome(target))
    }
    const inPrivateDir = !changesDir && isPrivateDir(dir, ctx)

    // 1. 비밀값 파일 — 읽기·쓰기·복사·source 모두. 존재 확인(ls, test)만 허용
    //    글롭은 셸이 펼치는 것(따옴표 밖의 * ? [)과 프로그램이 스스로 푸는 패턴만 본다.
    //    heredoc 본문은 글자마다 따옴표를 가리지 않았으므로 예전처럼 글롭으로 본다(보수적)
    //    echo · printf의 글은 화면이나 파일로 낼 때만 글이다 — `echo "(.env* 제외)"`의 글자는 파일이 아니다(2026-10-12 리허설). 출력이 다른 명령으로 가면
    //    — 파이프 · 명령 치환(따옴표 안 · heredoc 본문 포함, 변수에 담기 · printf -v도) · 괄호 · eval · 파이프로 가는 묶음 · 치환 뒤의 파이프 · > >(…) —
    //    그 명령이 글 속 이름의 파일을 읽을 수 있어 예전처럼 보고, 까닭은 envEcho로 준다 — 알리는 글이면 홀로 쓰면 된다(`cat $(echo .env.local)`,
    //    `echo .env.local | xargs cat`, 2026-10-13 총괄). .env.example · 참조 파일(.env*.op)은 비밀값 파일이 아니라 그대로 읽는다. 내는 곳(>)은 1-1이 본다
    const substring = !TEXT_ARG_COMMANDS.has(name)
    const textOnly = name === 'echo' || name === 'printf'
    const shownText =
      textOnly && !pipedOut && !feedsCommand && !inParen && !groupFeeds && !captured && !(name === 'printf' && /^-v/.test(args[0] ?? ''))
    const wordsTouchSecret = !shownText && words.some((word, i) => !isEnvExclusion(word, words[i - 1]) && refsSecretEnv(word, substring, ctx, globs[i]))
    const touchesSecret =
      (!textOnly && wordsTouchSecret) ||
      selfGlobPatterns(name, args).some(globMayMatchSecretEnv) ||
      (bodyRunner[index] !== null && heredocs.some((body) => refsSecretEnv(body, true, ctx, true)))
    if (touchesSecret && !EXISTENCE_ONLY.has(name)) escalate({ decision: 'deny', reason: REASON.env })
    else if (textOnly && wordsTouchSecret) escalate({ decision: 'deny', reason: REASON.envEcho })

    // 1-1. .env* 파일로 보내는 출력(>, >>, tee)은 값이 파일에 남는다 — 참조 파일이어도 막는다
    if (outputs.some(refsAnyEnvFile) || (name === 'tee' && args.some(refsAnyEnvFile))) {
      escalate({ decision: 'deny', reason: REASON.envOutput })
    }

    // 1-2. 1Password 참조 파일 — 읽기는 자유, 셸로 고치기 · 옮기기 · 지우기(cp · mv · sed -i · rm … — 감싼 것도)는 막는다. Edit · Write 도구로 고치면 가드가 줄마다
    //      이름=op://… 인지 본다(v35 12, 2026-10-18 — 예전에는 사람 확인). 판정할 수 없는 명령(nice cat · eval …)에 넘기면 예전처럼 사람 확인
    if (words.some((word) => refsReferenceFile(word, ctx)) && !readsReferenceOnly(name, args)) {
      escalate(editsFiles(name, args) ? { decision: 'deny', reason: REASON.referenceBash } : { decision: 'ask', reason: REASON.referenceUnknown })
    }

    // 1-3. 1Password 값을 파일로 저장하거나, 파이프 없이 화면에 내거나, 비밀 칸 값을 인자로 넘기는 명령
    if (name === 'op') {
      const reveals = opRevealsValue(args, words.some((word) => /^OP_FORMAT=json$/i.test(word)))
      if (reveals === 'file') escalate({ decision: 'deny', reason: REASON.opToFile })
      else if (reveals === 'stdout' && !pipedOut) escalate({ decision: 'deny', reason: REASON.opReveal })
      if (opPassesSecretArg(args)) escalate({ decision: 'deny', reason: REASON.opArgValue })
    }

    // 1-4. 키체인의 비밀값 꺼내기 (서비스 계정 토큰 등)
    if (name === 'security' && revealsKeychainSecret(args)) escalate({ decision: 'deny', reason: REASON.keychain })

    // 2. .gitignore를 무시하는 재귀 검색 — .env를 대소문자 모두로 명시적으로 뺐거나(R-235 — excludesEnvAnyCase), 참조 파일(*.op)만 고르거나, --include가 모두 .env와 맞지 않을 때만 허용.
    //    다른 명령이 돌리는 검색(timeout 5 grep -r · xargs grep -r)과 셸에 넘긴 글 속의 검색(bash -c 'grep -r …' · eval)도 본다(v35 11 — 예전에는 지나갔다).
    //    단순한 줄이면 decideShell 이 .env 를 빼는 꼴로 다시 써서 허락한다(rewriteSearch)
    const leak =
      searchLeak(name, args) ?? wrappedSearchLeak(name, args) ?? nested[index].map(({ line }) => searchLeakIn(line)).find((found) => found !== null) ?? null
    if (leak !== null) escalate({ decision: 'deny', reason: leak })

    // 13. 가드 · 권한 · 운영 설정 파일(.claude/hooks/ · .claude/settings*.json · .codex/hooks.json · .codex/rules/ · .mcp.json · .agents/skills/dev-deploy/project.md)에
    //     쓰기 · 지우기 · 옮기기 — 카드 권한 있으면 물음, 없으면 막음(v35, P44 · K7). 리디렉션 · tee · cp · mv · rm · sed -i · 인터프리터 코드 · 셸에 넘긴 글 속까지 본다.
    //     가드 사본은 /project-audit 의 install-guard.sh · audit.sh 가 바꾼다(SELF_FILE_WRITERS)
    {
      const base = dir ?? ctx.root
      const selfWrite =
        writesSelfFileOrWrapped(name, args, program, outputs, base, fs) ||
        (bodyRunner[index] !== null && !SHELLS.has(bodyRunner[index]) && heredocs.some((body) => writesFiles(body) && SELF_FILE_MENTION.test(body))) ||
        nested[index].some(({ line }) => selfWriteIn(line, base, fs))
      if (selfWrite) escalate({ decision: cardOf(ctx) ? 'ask' : 'deny', reason: REASON.selfFiles })
    }

    // 3. 프로젝트 문서(_core·_private) — 판정은 judgePrivate. core.sh·stage.sh(isTrustedWriter)는 인자를 보지 않는다(> 출력은 본다). git·gh의 글 인자(메시지·제목·본문) 속 글자는 보지 않고,
    //    기획 자료 폴더 안에서는 상대 경로도 기획 자료로 본다. cd·pushd·popd는 들어가기만 하므로 보지 않는다.
    //    파일 시스템을 보므로 글자만 보는 판정이 끝난 뒤에 돈다(fs, decide의 Bash)
    const receives = pipeFromPrivate
    let touchesPrivate = false
    let scriptReadsOnly = false
    if (fs && !changesDir && !assignOnly) {
      const base = dir ?? ctx.root
      const trusted = isTrustedWriter(name, args, program, base)
      const at = words.length - args.length
      // 읽기만 하는 perl · awk 한 줄 프로그램(코드 인자는 경로가 아니다)과 파일을 건드리지 않는 내장 명령(export · set …)은 cat 처럼 본다 (2026-10-15 R-168)
      const scriptCode =
        name === 'perl' && !perlEnvTouched ? perlReadsOnly(args, (j) => globs[at + j] === true) : AWKS.has(name) ? awkReadsOnly(args) : null
      scriptReadsOnly = scriptCode !== null
      const builtinOnly = NO_FILE_BUILTINS.has(name) && !args.some((w) => mentionsPrivate(w, base))
      const textValue = (j) =>
        TEXT_ARG_COMMANDS.has(name) && (/^--(message|title|body)=/.test(args[j]) || TEXT_VALUE_OPTION.test(args[j - 1] ?? ''))
      const spotOf = (word) => {
        const expanded = expandHome(word.replace(/^--[\w-]+=/, ''))
        const resolved = path.resolve(base, expanded)
        let spot = privateSpot(resolved)
        // `키=@파일`처럼 경로로 풀 수 없는 언급은 판정할 수 없다
        if (spot === null && mentionsPrivatePath(word)) spot = '?'
        // `content=@_core/plan.md`처럼 단어 속에 뿌리의 `_core` 경로가 박혀 있으면 그것도 판정할 수 없다
        else if (spot === null && mentionsCoreIn(word, base)) spot = '?'
        return { spot, resolved, unknown: /[$`]/.test(expanded) }
      }
      // 홀로 쓴 echo · printf(출력이 파이프 · > · 명령 치환 · 묶음으로 가지 않음)의 인자는 화면에 내는 글이다 — 글 속 `_core` · `_private` 낱말을
      // 경로로 보지 않는다(2026-10-13 apahere: `echo "== guard _core rules =="`가 물음). 출력이 어디로 가면 예전처럼 본다
      const standaloneText = textOnly && !pipedOut && outputs.length === 0 && !inParen && !groupRedirected
      // grep · rg · ag 의 검색어는 경로가 아니다 — 첫 위치 인자, 또는 -e · --regexp · -f 의 값(2026-10-13 apahere: `grep -v "^-- .*_private" a.sql`이 물음)
      const patterns = searchPatternArgs(name, args)
      // 빼는 패턴(-g '!_core' · --exclude-dir _core · ':!_core')은 그 곳을 읽지 않는다 (2026-10-13 4차 — jarvis R-120)
      const exclusions = searchExclusionArgs(name, args)
      const targets = []
      args.forEach((word, j) => {
        if (trusted || builtinOnly || standaloneText || textValue(j) || patterns.has(j) || exclusions.has(j) || scriptCode?.has(j)) return
        if (!inPrivateDir && !mentionsPrivate(word, base)) return
        if (/^[a-z][\w+.-]*:\/\//i.test(word) || (word.startsWith('-') && !mentionsPrivate(word, base))) return
        const spot = spotOf(word)
        if (spot.spot !== null) targets.push({ word, j, ...spot, glob: globs[at + j] === true })
      })
      // sort -o · --output 의 파일도 쓰는 곳이다(v35 9 — 예전에는 sort 를 읽기로만 보아 `sort -o _core/log.tsv …`가 지나갔다)
      const writes = [...outputs, ...(name === 'sort' ? sortOutputs(args) : [])]
        .filter((word) => inPrivateDir || mentionsPrivate(word, base))
        .map((word) => ({ word, ...spotOf(word), glob: false }))
        .filter((t) => t.spot !== null)
      const dirSpot = inPrivateDir ? privateSpot(path.resolve(base)) : null
      touchesPrivate = inPrivateDir || targets.length > 0 || writes.length > 0
      // 기획 자료 안의 프로그램을 돌리는 것도 판정할 수 없다
      if (mentionsPrivate(words[at - 1] ?? '', base)) escalate({ decision: 'ask', reason: REASON.privateOut })
      // for · select 반복문의 머리(for f in <목록>)는 실행하는 명령이 아니다. 목록이 기획 자료면 몸의 명령을 3-2처럼 본다 —
      // 읽기만 하는 몸은 그대로, 고치는 몸은 묻는다(2026-10-12 리허설: `for f in _private/docs/*.md; do cat "$f"; done`이 묻던 것)
      const loopHeader = name === 'for' || name === 'select'
      if (loopHeader && (inPrivateDir || targets.length > 0)) loopFromPrivate = true
      // `for f in $(find _core/raw …); do sed -i … "$f"; done`도 몸이 고치면 묻는다(2026-10-12 리허설 2차 24에서 찾은 빈틈)
      if (loopHeader) loopListPending = true
      else if (words[0] === 'do') loopListPending = false
      else if (loopListPending && touchesPrivate) loopFromPrivate = true
      // echo · printf 가 프로젝트 문서 경로를 다른 명령에 넘기면(파이프 · 명령 치환 · 괄호 · eval · 파이프로 가는 묶음) 그 명령이 무엇을 할지 판정할 수 없다 —
      // `echo _core/context.md | xargs cat | curl -d @- …`, `curl -d @$(echo _core/context.md) …`, `eval $(echo rm -rf _core)` (2026-10-13). 파일로 내는 것(>)은 글이라 그대로
      if (textOnly && targets.length > 0 && (pipedOut || inParen || groupPiped)) escalate({ decision: 'ask', reason: REASON.privateOut })
      const result = loopHeader ? null : judgePrivate(name, args, targets, writes, dirSpot, gitEnv, scriptReadsOnly || builtinOnly, globs.slice(at), base)
      if (result) escalate(result)

      // 3-0. 인터프리터에 인자로 넘긴 코드(-c·-e)가 기획 자료를 가리키거나 기획 자료 안에서 돌고 파일을 쓰면 막는다 (2026-10-09)
      if (INTERPRETERS.has(name) && !SHELLS.has(name) && name !== 'psql') {
        const code = inlineCode(name, args)
        if (code !== null && (inPrivateDir || targets.length > 0 || mentionsPrivate(code, base)) && writesFiles(code)) {
          escalate({ decision: 'deny', reason: REASON.privateScript })
        }
      }

      // 3-1. 프로그램이 실행하는 heredoc 본문(bash <<'EOF' … EOF, bodyRunner)이 기획 자료를 가리키거나 기획 자료 안에서 돌면,
      //      셸 본문은 명령 줄처럼 판정하고 그 밖의 프로그램(python3 - <<'EOF' …)의 본문은 판정할 수 없어 묻는다 (2026-10-07 jarvis 검토).
      //      그 본문이 파일을 쓰거나 지우면 묻지 않고 막는다 — Edit·Write 도구로 고치라는 까닭을 에이전트가 받는다 (2026-10-09)
      if (bodyRunner[index] !== null) {
        for (const body of heredocs) {
          if (!inPrivateDir && !mentionsPrivate(body, base)) continue
          if (SHELLS.has(bodyRunner[index])) {
            const inner = checkBash(body, { ...ctx, cwd: base }, fs)
            if (inner) escalate(inner)
          } else if (bodyRunner[index] !== 'psql' && writesFiles(body)) {
            escalate({ decision: 'deny', reason: REASON.privateScript })
          } else {
            escalate({ decision: 'ask', reason: REASON.privateOut })
          }
        }
      }

      // 3-2. 기획 자료를 가리키는 명령의 출력을 파이프로 받는 명령 — find _private/raw -type f | xargs rm,
      //      … | while read f; do rm "$f"; done. 읽기만 하는 명령은 넘기고, xargs는 돌리는 명령으로, 반복문은 몸의 명령으로,
      //      인터프리터는 받은 것을 판정할 수 없는 명령으로 본다 (2026-10-07 jarvis 검토). 읽기만 하는 perl · awk 한 줄 프로그램은 읽기만 하는 명령이고,
      //      awk 도 인터프리터로 본다 — `cat _core/x | awk '{ system(…) }'`가 지나가던 빈틈 (2026-10-15 R-168)
      if (receives || loopFromPrivate) {
        if (name === 'done') loopFromPrivate = false
        else if (receives && name === 'read' && ['while', 'until'].includes(words[0] ?? '')) loopFromPrivate = true
        else if (name === 'xargs') {
          const inner = xargsCommand(args)
          if (inner.name !== '' && !readsOnly(inner.name, inner.args)) escalate({ decision: 'ask', reason: REASON.privateBulk })
        } else if (name === 'parallel') escalate({ decision: 'ask', reason: REASON.privateBulk })
        else if (receives && (INTERPRETERS.has(name) || AWKS.has(name)) && !scriptReadsOnly) escalate({ decision: 'ask', reason: REASON.privateOut })
        else if (loopFromPrivate && !LOOP_NOOPS.has(name) && !readsOnly(name, args) && !scriptReadsOnly) {
          escalate({ decision: 'ask', reason: REASON.privateBulk })
        }
      }
    }
    // 읽기만 하는 명령(grep, sort …, 읽기만 하는 perl · awk)을 거쳐도 목록은 이어진다
    pipeFromPrivate = pipedOut && (touchesPrivate || (receives && (readsOnly(name, args) || scriptReadsOnly)))

    // 4. 연결된 원격 DB 초기화 (--linked, --linked=true, --db-url …)
    if (name === 'supabase' && args.includes('db') && args.includes('reset')) {
      if (args.some((a) => /^--linked(=|$)/.test(a) || a.startsWith('--db-url'))) {
        escalate({ decision: 'deny', reason: REASON.dbReset })
      }
    }

    // 5. 커밋 전 검사 우회 — 막는다: --no-verify · -n, 훅 경로 지우기, core 절 지우기 · 이름 바꾸기, 한 번만 덮어쓰기(-c · --config-env ·
    //    GIT_CONFIG_PARAMETERS · GIT_CONFIG_KEY_n), .githooks 밖으로 바꾸기, 범위가 넓은 설정(--global · --system)과 다른 설정 파일(--file · -f · --blob)에
    //    적기(.githooks여도). 그대로: 이 저장소에 .githooks(./.githooks · .githooks/)로 두기(--local · --worktree · 범위 없음)와 조회(--get · get, 값 없는
    //    `git config core.hooksPath`). 셸에 넘긴 명령 줄(bash -c · sh -c · zsh -c · bash -lc · eval)과 명령 치환 속도 본다 — commitChecksBypassed, 깊이는 6과 같다
    //    (2026-10-13 사용자 결정 — 바꾸기를 묻던 것을 jarvis 가드 5번처럼 값으로 가름, 같은 날 총괄 검토로 빈틈을 더함).
    //    다른 명령이 돌리는 git(timeout · nice · stdbuf · corepack pnpm exec · sudo -u … · xargs · find -exec — 6번처럼 인자에서 git 낱말을 찾는다, 글만 내는
    //    echo · printf · man 은 빼고)과, 셸이 다시 명령 줄로 읽는 글 — env -S '…' · --split-string=…, 셸이 받는 heredoc 본문 · here-string(bash <<'EOF' ·
    //    sh <<EOF · cat <<'EOF' | sh · bash <<< '…'), 셸에 넘긴 echo · printf의 글(echo '…' | bash) — 도 본다. 파일에 쓰기만 하는 본문(cat <<'EOF' > notes.md),
    //    커밋 메시지(git commit -F - <<'EOF' · -m "$(cat <<'EOF' …)"), 홀로 쓴 echo는 글이다. 입력에서 받은 낱말을 끝에 붙이는 xargs · parallel · fd 가 돌리는
    //    값 없는 `git config core.hooksPath`는 값이 입력에서 오므로 막는다 (2026-10-13 총괄 — jarvis 비교 도구가 찾은 빈틈).
    //    줄 이음 뒤의 명령(`cd x && \⏎git commit --no-verify`, `git \⏎config …`), dash · ksh · mksh · busybox sh 같은 셸이 받는 줄, export · declare · typeset ·
    //    readonly · local 로 대입한 변수(`export K=core.hooksPath; git config $K /tmp/hooks`), 값을 `…` 로 준 것(`git config core.hooksPath \`mktemp -d\``),
    //    $'…' 로 쓴 이름(`$'git' commit --no-verify`, `git config $'core.\x68ooksPath' …`)도 막는다 — 나누기(splitCommands)에서 고쳐 1 · 4 · 6번도 같이 본다
    //    (2026-10-13 총괄 — jarvis 비교 도구 2차).
    //    4차(2026-10-13 총괄 — jarvis 정리 세션의 원칙 검토, 확장 5번을 지우려고): 이름 앞의 명령 치환(`git -C $(pwd) config --unset core.hooksPath` — 셸이 넘기는
    //    인자 그대로 나눈 꼴을 checkBash 가 commitChecksBypassed 로 더 본다), -c 앞의 옵션 값(`bash -euo pipefail -c '…'` — shellInvocation), 인자로 세던 here-string ·
    //    입력 리디렉션(`<<<.githooks`), 낱말에 붙은 프로세스 치환(`.githooks<(true)`), 묶음 · 리디렉션이 붙은 대입(`{ K=…; }` · `K=… >/dev/null`), 서브셸 안의 대입
    //    (`(export HOME=.githooks)`), 작은따옴표 안의 $(`'$V'`), 치환 속 따옴표 친 괄호(matchParen), 주석 판정(값 펼치기 안의 # · \ 뒤의 # · 주석 속 \"), 값을 받는
    //    옵션의 값(`--comment --get`), 이름을 풀지 못한 명령(`$G commit --no-verify`)과 이름 앞의 모르는 낱말(`git config $(…) core.hooksPath`)도 막는다.
    //    검색 · 읽기 명령의 인자(`rg -n git commit --no-verify docs/`)와 스크립트 파일을 돌리는 셸이 받는 입력(`bash x.sh <<'EOF'`)은 명령이 아니다
    const fixed = fixedWords(segments[index])
    const bypass = commitCheckBypass(words, name, args, cut, fixed)
    if (bypass !== null) escalate({ decision: 'deny', reason: bypass })
    for (const { line } of nested[index]) {
      const nestedBypass = commitChecksBypassed(line)
      if (nestedBypass !== null) escalate({ decision: 'deny', reason: nestedBypass })
    }

    // 6. 위험한 push — 사람이 승인한다 (공통 규칙 0. 2026-10-13 사용자 결정: 작업 가지 push는 묻지 않는다 — 비파괴적이고 되돌릴 수 있다.
    //    설정의 allow에 `Bash(git push *)`를 두고(install-guard.sh), 위험한 꼴만 여기서 묻는다. jarvis 가드 8번을 틀로 옮김, R-112).
    //    묻는 꼴: 기본 가지(main · master · 원격이 알려 준 기본 가지)로 / 가지를 적지 않음(`git push`, `git push origin`, HEAD · @ — 훅은 지금 가지를
    //    모른다) / 강제(-f · 묶은 -fu · --force* · +가지) / 지우기(--delete · -d · :가지) / 광역(--all · --branches · --mirror · --prune · --tags ·
    //    --follow-tags · refs/tags/ · 와일드카드). 셸에 넘긴 명령 줄(bash -c · eval)과 명령 치환 속의 push도 본다 — gitLineVerdict.
    //    다른 명령이 돌리는 push(timeout · nice …, 인자를 입력에서 받는 xargs · find -exec 는 늘), 설정 덮어쓰기(-c · --config-env · GIT_CONFIG_*)와
    //    함께인 push, `--git-dir 경로 push`처럼 전역 옵션 값 뒤의 push도 묻는다 (2026-10-13 총괄 검토).
    //    셸이 다시 명령 줄로 읽는 글(5번과 같은 nestedCommandLines — env -S '…', 셸이 받는 heredoc 본문 · here-string, 셸에 넘긴 echo · printf의 글,
    //    다른 명령이 돌리는 셸의 -c 글. xargs · find -exec 가 돌리는 셸 속의 push는 늘)도 본다 (2026-10-13 총괄 — jarvis 비교 도구가 찾은 빈틈).
    //    줄 이음 뒤의 push(`pnpm test && \⏎git push origin main`), dash · ksh 가 받는 줄, export · declare 로 대입한 가지(`declare B=main; git push origin $B`),
    //    $'…' 로 쓴 이름 · 가지(`$'git' push origin main`, `git push origin $'main'`)도 묻는다 (2026-10-13 총괄 — jarvis 비교 도구 2차).
    //    4차(2026-10-13): 이름 앞의 명령 치환(`git -C $(pwd) push origin main`), -c 앞의 옵션 값(`bash -euo pipefail -c 'git push origin main'`), 옵션 값의 find
    //    (`env -u find git --namespace ';' push origin main` — 4dab3f51 은 물었다), 풀지 못한 변수 · 명령 치환으로 준 가지와 원격(`git push origin "$B"`,
    //    `git push -u origin "$(git branch --show-current)"` — 훅은 그 값을 모른다)도 묻는다.
    //    v35(2026-10-18 R-265, guard-v35.tsv 1~8): 이름 없는 push 는 지금 가지 · @{push} 로 풀어 작업 가지면 통과(분리된 HEAD · push.default=matching ·
    //    remote.*.push · 풀지 못함은 물음), refspec 은 받는 쪽으로(HEAD:main 은 기본 가지 push), -c credential.helper(빈 값 · gh) 만 예외,
    //    --force-with-lease · --force-if-includes 는 작업 가지 통과 · 기본 가지 막음, -f · --force · +가지는 막음(--force-with-lease 로 다시 — 「한 번에 승인」 B-2),
    //    원격 가지 지우기는 같은 이름 로컬 가지가 있으면 통과 · 기본 가지 막음 · 로컬 사본 없음 · 태그 물음. 같은 자리에서 git branch -D(원격에 없는 커밋 — 물음),
    //    기본 가지 커밋(카드 권한 없는 자리 — 막음), git clean -x · -X · git stash -a · --all(막음)도 본다 — commandGitVerdict
    if (words.some((w) => GIT_CONFIG_ASSIGNMENT.test(w))) gitConfigEnv = true
    const gitHere = commandGitVerdict(words, name, args, dir ?? ctx.root, fs, gitConfigEnv, fixed, ctx)
    if (gitHere) escalate(gitHere)
    for (const { line, fed } of nested[index]) {
      const inner = gitLineVerdict(line, dir ?? ctx.root, fs, 0, fed, ctx)
      if (inner) escalate(inner)
    }
  }
  return decision
}

// ---------- 되풀이 검색(2 · 11) ----------
const GREPS = new Set(['grep', 'egrep', 'fgrep'])
/** 그 검색이 .env 를 읽을 수 있으면 막는 까닭(REASON.grep · REASON.rg), 아니면 null — .gitignore 를 무시하는 재귀 grep · rg --no-ignore(-uu) 가 .env 를 대소문자 모두로 빼지 않을 때 */
function searchLeak(name, args) {
  if (GREPS.has(name)) {
    const recursive = args.some((a) => /^--(dereference-)?recursive$/.test(a) || /^-[A-Za-z]*[rR][A-Za-z]*$/.test(a))
    const excludesEnv = args.some((a) => a.startsWith('--exclude=') && excludesEnvAnyCase(a.slice('--exclude='.length), false))
    return recursive && !excludesEnv && !includesOnlyReferenceFiles(args) && !includesNoEnvFiles(args) ? REASON.grep : null
  }
  if (name === 'rg') {
    const noIgnore = args.some((a) => /^--no-ignore/.test(a) || /^-[A-Za-z]*u[A-Za-z]*u/.test(a))
    const excludesEnv = args.some((a, i) => rgExcludesEnv(a, args[i - 1]))
    return noIgnore && !excludesEnv ? REASON.rg : null
  }
  return null
}
/**
 * 다른 명령이 돌리는 검색(timeout 5 grep -r · nice rg -uu · xargs grep -r · find … -exec grep -r)의 까닭 — 인자에서 처음 나오는 grep · rg 뒤를 그 인자로 본다.
 * git(git grep 은 추적하는 파일만 본다) · 글만 내거나 읽기만 하는 명령 · 인터프리터(스크립트의 인자)의 인자는 아니다
 */
function wrappedSearchLeak(name, args) {
  if (GREPS.has(name) || name === 'rg' || name === 'git' || name === 'ag' || runsNoArgs(name) || INTERPRETERS.has(name) || AWKS.has(name)) return null
  for (let k = 0; k < args.length; k++) {
    const word = path.posix.basename(args[k] ?? '')
    if (word === 'git') return null
    if (GREPS.has(word) || word === 'rg') return searchLeak(word, args.slice(k + 1))
  }
  return null
}
/** 셸이 다시 명령 줄로 읽는 글(bash -c · eval · env -S · 셸이 받는 heredoc 본문 …) 속의 검색 까닭 — 그 글의 감싼 명령 · 또 넘긴 글 · 명령 치환까지 */
function searchLeakIn(command, depth = 0) {
  if (depth > 3) return null
  for (const { segments, quotedBodies } of splitModes(command)) {
    resolveShellVars(segments)
    const nested = nestedCommandLines(segments, bodyRunners(segments, '.'))
    for (const [i, { words }] of segments.entries()) {
      const { name, args } = commandOf(words)
      const found = searchLeak(name, args) ?? wrappedSearchLeak(name, args) ?? nested[i].map(({ line }) => searchLeakIn(line, depth + 1)).find((r) => r !== null) ?? null
      if (found !== null) return found
    }
    for (const body of substitutionBodies(segments, quotedBodies)) {
      const found = searchLeakIn(body, depth + 1)
      if (found !== null) return found
    }
  }
  return null
}
/** 11. 다시 쓸 때 넣는 꼴 — grep 은 대소문자를 다 덮는 글자 묶음, rg 는 대소문자를 가리지 않는 --iglob (REASON.grep · REASON.rg 의 안내와 같다) */
const SEARCH_EXCLUDE = { grep: " --exclude='.[eE][nN][vV]*'", rg: " --iglob '!.env*'" }
/** 다시 쓸 때 검색 이름 앞에 와도 되는 낱말 — commandOf 가 건너뛰는 감싸는 명령(옵션 없이) */
const REWRITE_WRAPPERS = new Set(['sudo', 'env', 'command', 'time', 'nohup', 'exec'])
/**
 * 11. 단순한 줄의 되풀이 grep · rg --no-ignore 에 .env 를 빼는 꼴을 넣은 명령 — 그 grep · rg 이름 바로 뒤에 넣는다(`grep -rn KEY .` → `grep --exclude='.[eE][nN][vV]*' -rn KEY .`).
 * 단순한 줄: 명령 치환 · 프로세스 치환 · 괄호 · 묶음 · 중괄호 · heredoc · here-string · 뒤에서 돌기(&) · 줄바꿈 · 주석 · $'…' · $"…" 가 없고, 검색 이름이 그 명령의 맨 앞
 * (앞의 대입 · 옵션 없는 감싸는 낱말 뒤)인 줄 — ; · && · || · | 와 리디렉션은 된다. 셸에 넘긴 글(bash -c · eval)과 감싸 돌리는 검색(xargs grep)은 바꾸지 않는다.
 * 바꿀 것이 없거나 단순한 줄이 아니면 null. 바꾼 줄은 가드가 처음부터 다시 판정한다 — 여기서 잘못 나눠도 그 판정이 막으면 막음 그대로다
 */
function rewriteSearch(command) {
  if (/[\n\r`]|\$[('"{]|[<>]\(|<</.test(command)) return null
  const n = command.length
  const readWord = (start) => {
    let k = start
    let text = ''
    while (k < n) {
      const c = command[k]
      if (c === "'") {
        const end = command.indexOf("'", k + 1)
        if (end < 0) return null
        text += command.slice(k + 1, end)
        k = end + 1
      } else if (c === '"') {
        let m = k + 1
        for (; m < n && command[m] !== '"'; m++) {
          if (command[m] === '\\' && m + 1 < n && '$`"\\'.includes(command[m + 1])) m++
          text += command[m]
        }
        if (m >= n) return null
        k = m + 1
      } else if (c === '\\') {
        if (k + 1 >= n) return null
        text += command[k + 1]
        k += 2
      } else if (/[\s;&|<>(){}]/.test(c)) break
      else {
        text += c
        k++
      }
    }
    return k === start ? null : { text, end: k }
  }
  const segments = [[]]
  let i = 0
  while (i < n) {
    const c = command[i]
    if (c === ' ' || c === '\t') {
      i++
      continue
    }
    if (c === ';') {
      segments.push([])
      i++
      continue
    }
    if (c === '|') {
      if (command[i + 1] === '&') return null
      i += command[i + 1] === '|' ? 2 : 1
      segments.push([])
      continue
    }
    if (c === '&' && command[i + 1] === '&') {
      segments.push([])
      i += 2
      continue
    }
    if (c === '>' || c === '<' || (c === '&' && command[i + 1] === '>')) {
      // 리디렉션(> · >> · >& · >| · < · <& · &>) — 대상 낱말은 명령의 인자가 아니다
      i++
      while ('>&|'.includes(command[i] ?? ' ')) i++
      while (command[i] === ' ' || command[i] === '\t') i++
      const target = readWord(i)
      if (target === null) return null
      i = target.end
      continue
    }
    if ('&(){}#'.includes(c)) return null
    const word = readWord(i)
    if (word === null) return null
    i = word.end
    // 2> 처럼 리디렉션 바로 앞의 숫자는 파일 디스크립터다
    if (/^\d+$/.test(word.text) && (command[i] === '>' || command[i] === '<')) continue
    segments[segments.length - 1].push(word)
  }
  const inserts = []
  for (const words of segments) {
    let k = 0
    while (k < words.length && (ASSIGNMENT.test(words[k].text) || REWRITE_WRAPPERS.has(words[k].text))) k++
    if (k >= words.length) continue
    const name = path.posix.basename(words[k].text)
    const tool = GREPS.has(name) ? 'grep' : name === 'rg' ? 'rg' : null
    if (tool === null || searchLeak(name, words.slice(k + 1).map((w) => w.text)) === null) continue
    inserts.push({ at: words[k].end, text: SEARCH_EXCLUDE[tool] })
  }
  if (inserts.length === 0) return null
  let out = command
  for (const { at, text } of inserts.sort((a, b) => b.at - a.at)) out = `${out.slice(0, at)}${text}${out.slice(at)}`
  return out
}

// ---------- 가드 · 권한 · 운영 설정 파일(13) ----------
/** 고치면 안전망이 풀리는 파일 — 프로젝트(와 홈)의 그 자리. 대소문자는 가리지 않는다(macOS 기본 APFS 에서 .Claude/Settings.json 도 같은 파일) */
const SELF_FILE = /(?:^|\/)(?:\.claude\/hooks\/.+|\.claude\/settings[^/]*\.json|\.codex\/hooks\.json|\.codex\/rules\/.+|\.mcp\.json|\.agents\/skills\/dev-deploy\/project\.md)$/i
/** 그 파일을 품은 폴더 — 지우거나 옮기거나 폴더째 복사해 넣으면 그 파일도 함께다 */
const SELF_DIR = /(?:^|\/)(?:\.claude(?:\/hooks)?|\.codex(?:\/rules)?|\.agents(?:\/skills(?:\/dev-deploy)?)?)\/*$/i
/** 스크립트 코드 속의 그 파일 이름 — 쓰는 코드(writesFiles)와 함께일 때만 쓰기로 본다 */
const SELF_FILE_MENTION = /\.claude\/hooks\/|\.claude\/settings[^/'"\s]*\.json|\.codex\/(?:hooks\.json|rules\/)|\.mcp\.json|dev-deploy\/project\.md/i
/** 그 파일을 바꾸는 것이 일인 스크립트 — 홈의 스킬 폴더에 있는 것만(TRUSTED_WRITERS 와 같은 자리). 그 인자는 보지 않는다(리디렉션은 본다) */
const SELF_FILE_WRITERS = ['project-setting/scripts/install-guard.sh', 'project-setting/scripts/audit.sh']
const isSelfFile = (resolved) => SELF_FILE.test(resolved)
/** 그 명령이나 그것이 돌리는 고치는 명령(nice cp · timeout 5 tee · xargs rm …)이 그 파일에 쓰는가 */
function writesSelfFileOrWrapped(name, args, program, outputs, base, fs) {
  if (writesSelfFile(name, args, program, outputs, base, fs)) return true
  const inner = fileEditor(name, args)
  return inner !== null && inner.name !== name && writesSelfFile(inner.name, inner.args, inner.program, [], base, fs)
}
function isSelfFileWriter(name, args, program, base) {
  const script = TRUSTED_WRITER_SHELLS.has(name) ? (args.find((a) => !a.startsWith('-')) ?? '') : program
  if (!HOME || script === '') return false
  const resolved = path.resolve(base, expandHome(script))
  return ['.agents/skills', '.claude/skills'].some((dir) => SELF_FILE_WRITERS.some((w) => resolved === path.join(HOME, dir, w)))
}
/** 셸 명령 하나가 그 파일에 쓰거나 그 파일(폴더)을 지우거나 옮기는가 — 리디렉션 · tee · truncate · cp · ln · ditto · install · rsync 의 받는 곳 · mv 양쪽 · rm 류 ·
 *  sed · perl · ruby 의 -i · dd of= · sort -o · curl · wget 의 받는 곳 · git rm · git mv · 인터프리터에 넘긴 코드. 값을 모르는 낱말(변수 · 명령 치환)은 보지 않는다 */
function writesSelfFile(name, args, program, outputs, base, fs) {
  const resolve = (word) => (typeof word !== 'string' || word === '' || /[$`]/.test(word) ? null : path.resolve(base, expandHome(word)))
  const hits = (word, folders = false) => {
    const resolved = resolve(word)
    return resolved !== null && (isSelfFile(resolved) || (folders && SELF_DIR.test(resolved)))
  }
  if (outputs.some((word) => hits(word))) return true
  if (isSelfFileWriter(name, args, program, base)) return false
  const positional = args.filter((a) => a === '-' || !a.startsWith('-'))
  if (name === 'tee' || name === 'truncate') return positional.some((word) => hits(word))
  if (PRIVATE_REMOVERS.has(name) || name === 'mv') return positional.some((word) => hits(word, true))
  if (['cp', 'ln', 'ditto', 'install', 'rsync'].includes(name)) {
    // 받는 곳은 마지막 위치 인자 — 줄 끝 주석의 낱말(# 부터)은 인자가 아니다
    const hash = positional.findIndex((word) => word.startsWith('#'))
    const places = hash < 0 ? positional : positional.slice(0, hash)
    if (places.length < 2) return false
    const dest = places[places.length - 1]
    const destPath = resolve(dest)
    if (destPath === null) return false
    if (isSelfFile(destPath)) return true
    let isDir = dest.endsWith('/') || SELF_DIR.test(destPath)
    if (!isDir && fs) isDir = lstatSync(destPath, { throwIfNoEntry: false })?.isDirectory() === true
    if (!isDir) return false
    return places.slice(0, -1).some((word) => {
      const into = path.join(destPath, path.posix.basename(expandHome(word)))
      return isSelfFile(into) || SELF_DIR.test(into)
    })
  }
  if (['sed', 'perl', 'ruby'].includes(name) && args.some((a) => /^-[A-Za-z]*i/.test(a) || a.startsWith('--in-place'))) return positional.some((word) => hits(word))
  if (name === 'dd') return args.some((a) => a.startsWith('of=') && hits(a.slice(3)))
  if (name === 'sort') return sortOutputs(args).some((word) => hits(word))
  if (Object.hasOwn(DOWNLOAD_OUTPUT_OPTIONS, name)) return args.some((a, j) => isDownloadOutput(name, args, j) && hits(a.replace(/^--[\w-]+=/, '')))
  if (name === 'git') {
    const at = gitSubcommandIndex(args)
    const sub = args[at]
    if ((sub === 'rm' && !args.includes('--cached')) || sub === 'mv') return args.slice(at + 1).some((word) => !word.startsWith('-') && hits(word, true))
    return false
  }
  if (INTERPRETERS.has(name) && !SHELLS.has(name)) {
    const code = inlineCode(name, args)
    return code !== null && writesFiles(code) && SELF_FILE_MENTION.test(code)
  }
  return false
}
/** 파일을 고치거나 옮기거나 지우는 셸 명령인가 — sed · perl · ruby 는 -i 일 때, sort 는 -o 일 때 */
const FILE_EDITORS = new Set(['cp', 'mv', 'ln', 'ditto', 'install', 'rsync', 'tee', 'truncate', 'touch', 'dd', ...PRIVATE_REMOVERS])
function editsFileDirectly(name, args) {
  if (FILE_EDITORS.has(name)) return true
  if (['sed', 'perl', 'ruby'].includes(name)) return args.some((a) => /^-[A-Za-z]*i/.test(a) || a.startsWith('--in-place'))
  return name === 'sort' && sortOutputs(args).length > 0
}
/**
 * 그 명령이나 그것이 돌리는 명령(nice · timeout · xargs · eval … 의 인자에서 처음 나오는 고치는 명령)이 파일을 고치는가 — 12 · 13번이 쓴다.
 * 글만 내거나 읽기만 하는 명령 · 인터프리터(스크립트의 인자) · git 의 인자는 명령이 아니다. { name, args } 로 그 명령을, 없으면 null
 */
function fileEditor(name, args) {
  if (editsFileDirectly(name, args)) return { name, args }
  if (runsNoArgs(name) || INTERPRETERS.has(name) || AWKS.has(name) || name === 'git') return null
  for (let k = 0; k < args.length; k++) {
    const word = path.posix.basename(args[k] ?? '')
    if (word === 'git') return null
    if (editsFileDirectly(word, args.slice(k + 1))) return { name: word, args: args.slice(k + 1), program: args[k] }
  }
  return null
}
const editsFiles = (name, args) => fileEditor(name, args) !== null
/** 셸이 다시 명령 줄로 읽는 글 속에서 그 파일에 쓰는가 — cd 를 따라가고, 또 넘긴 글 · 명령 치환 · 인터프리터가 받는 heredoc 본문까지 */
function selfWriteIn(command, base, fs, depth = 0) {
  if (depth > 3) return false
  for (const { segments, quotedBodies } of splitModes(command)) {
    resolveShellVars(segments)
    const runners = bodyRunners(segments, base)
    const nested = nestedCommandLines(segments, runners)
    let at = base
    for (const [i, { words, outputs, heredocs }] of segments.entries()) {
      const { name, args, program } = commandOf(words)
      if (name === 'cd' || name === 'pushd') {
        const target = args.find((a) => !a.startsWith('-'))
        at = target === undefined ? HOME || at : path.resolve(at, expandHome(target))
        continue
      }
      if (writesSelfFileOrWrapped(name, args, program, outputs, at, fs)) return true
      if (runners[i] !== null && !SHELLS.has(runners[i]) && heredocs.some((body) => writesFiles(body) && SELF_FILE_MENTION.test(body))) return true
      if (nested[i].some(({ line }) => selfWriteIn(line, at, fs, depth + 1))) return true
    }
    if (substitutionBodies(segments, quotedBodies).some((body) => selfWriteIn(body, base, fs, depth + 1))) return true
  }
  return false
}

// ---------- 1Password 참조 파일의 내용(12) ----------
/** 참조 줄 — audit.sh 의 @op-ref-value 와 같은 꼴: 이름=op://…(큰따옴표로 싸도 됨, 뒤에 주석) */
const REFERENCE_LINE = /^[A-Za-z_][A-Za-z0-9_]*=(?:"op:\/\/[^"]+"|op:\/\/\S+)(?:\s+#.*)?\s*$/
/** 글이 줄마다 참조 · 주석 · 빈 줄인가 — 아니면 값일 수 있다 */
function referenceTextOk(text) {
  return String(text).split(/\r?\n/).every((line) => /^\s*(?:#.*)?$/.test(line) || REFERENCE_LINE.test(line))
}
/** 지금 파일의 글(1MB 까지) — 없거나 못 읽으면 null */
function currentText(filePath, ctx) {
  try {
    const resolved = path.resolve(ctx.cwd ?? ctx.root, String(filePath))
    if (statSync(resolved).size > 1 << 20) return null
    return readFileSync(resolved, 'utf8')
  } catch {
    return null
  }
}
/** 고친 뒤의 글 — 지금 파일에 바꿀 글(old_string)이 있으면 바꾼 뒤의 파일 전체, 없으면(못 읽음 포함) 새 글만. 줄 일부만 바꾸는 Edit 도 파일 전체로 본다 */
function applyEdits(filePath, edits, ctx) {
  let text = currentText(filePath, ctx)
  for (const edit of edits) {
    const old = typeof edit?.old_string === 'string' ? edit.old_string : ''
    const next = String(edit?.new_string ?? '')
    if (text === null || old === '' || !text.includes(old)) return edits.map((e) => String(e?.new_string ?? '')).join('\n')
    text = edit.replace_all ? text.split(old).join(next) : text.replace(old, () => next)
  }
  return text ?? ''
}

/**
 * 같은 내용 검사 건너뛰기의 통과 기록(.githooks/check-once.mjs 가 `git rev-parse --git-path check-once-passed`에 둠, 2026-10-17 R-224).
 * 그 스크립트는 이 이름을 인자로 받지 않으니, 이름이 든 명령 · 고치기는 모두 손으로 쓰는 것이다. Bash 에서는 언급만 해도 막는다(읽기 · 조회 포함) —
 * 읽기는 Read 도구로(checkPath 는 쓰기만 막는다). 명령에서 쓰기만 골라 막으면 풀어 쓴 꼴마다 새 빈틈이 생기기 쉬워 엄하게 둔다(2026-10-17 R-235)
 */
const CHECK_RECORD = 'check-once-passed'
function mentionsCheckRecord(command) {
  if (command.includes(CHECK_RECORD)) return true
  try {
    // 따옴표를 나눠 붙인 이름('check-once-'"passed") · 변수로 이은 이름(check-once-$X)은 셸이 푼 낱말과 리디렉션 대상으로 본다
    if (simpleCommands(command).some(({ name, args }) => [name, ...args].some((w) => w.includes(CHECK_RECORD)))) return true
    for (const { segments } of splitModes(command)) {
      resolveShellVars(segments)
      if (segments.some(({ words, outputs }) => [...words, ...outputs].some((w) => w.includes(CHECK_RECORD)))) return true
    }
    return false
  } catch {
    return false
  }
}

/**
 * 파일 하나를 읽거나(mode 'read') 고치는(mode 'write') 판정. newText: 고친 뒤의 글(또는 그것을 돌려주는 함수) — 1Password 참조 파일의 내용 검사(12)에만 쓴다
 */
function checkPath(filePath, mode, ctx, newText = null) {
  if (typeof filePath !== 'string' || filePath === '') return null
  if (isSecretEnvPath(filePath, ctx)) return { decision: 'deny', reason: REASON.env }
  if (mode === 'write' && path.posix.basename(filePath) === CHECK_RECORD) return { decision: 'deny', reason: REASON.checkRecord }
  // 13. 가드 · 권한 · 운영 설정 파일 — 카드 권한 있으면 물음, 없으면 막음(v35, P44 · K7)
  if (mode === 'write' && isSelfFile(path.resolve(ctx.cwd ?? ctx.root, expandHome(filePath)))) return { decision: cardOf(ctx) ? 'ask' : 'deny', reason: REASON.selfFiles }
  if (mode === 'write' && isReferenceFile(filePath, ctx)) {
    // 12. 고친 뒤의 글이 줄마다 이름=op://… · 주석 · 빈 줄이면 통과, 아니면 막는다(값일 수 있음 — v35, 예전에는 사람 확인). 글을 모르면 막는다
    let text = null
    try {
      text = typeof newText === 'function' ? newText() : newText
    } catch {
      text = null
    }
    return typeof text === 'string' && referenceTextOk(text) ? null : { decision: 'deny', reason: REASON.reference }
  }
  if (mode === 'write' && isUnderPrivate(filePath, ctx.root)) {
    // 기획 자료는 묻지 않고 고친다(공통 규칙 8, 2026-10-07). raw/에 이미 있는 원본만 사용자 확인. 진행 파일은 core.sh · stage.sh만(2026-10-12)
    const resolved = path.resolve(ctx.root, filePath)
    if (isProgressFile(resolved)) return { decision: 'deny', reason: REASON.progress }
    const spot = privateSpot(resolved)
    if (spot !== null && isRawSpot(spot) && existsSync(resolved)) return { decision: 'ask', reason: REASON.privateRaw }
  }
  return null
}

/**
 * Codex 의 파일 고치기 도구(apply_patch) — Codex 훅은 Claude 와 같은 꼴(tool_name · tool_input · cwd)로 부르고, 셸은 Bash,
 * 파일 고치기는 tool_input.command 에 패치 글을 준다(codex-cli 0.153.4 실측, 2026-10-12). 패치의 파일마다 Edit·Write 와 같게 보고
 * 가장 엄한 판정을 낸다. 지우기(Delete)와 옮기기(Move to 의 원래 파일)는 고치기로 본다 — raw/ 원본이면 묻고, 진행 파일이면 막는다.
 * 1Password 참조 파일은 그 파일 몫의 더하는 줄(+)로 내용을 보고(12), 지우거나 다른 이름으로 옮기면 묻는다
 */
function checkPatch(patch, ctx) {
  let worst = null
  const lines = patch.split('\n')
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^\*\*\* (Add File|Update File|Delete File|Move to): (.+?)\s*$/)
    if (!m) continue
    const [, op, file] = m
    const added = []
    for (let k = i + 1; k < lines.length && !lines[k].startsWith('*** '); k++) if (lines[k].startsWith('+')) added.push(lines[k].slice(1))
    const leaves = op === 'Delete File' || (op === 'Update File' && /^\*\*\* Move to: /.test(lines[i + 1] ?? ''))
    const result =
      leaves && isReferenceFile(file, ctx) ? { decision: 'ask', reason: REASON.referenceDelete } : checkPath(file, 'write', ctx, added.join('\n'))
    worst = stricter(worst, result)
  }
  return worst
}

/**
 * 셸 명령을 돌리는 도구 — Bash 와 같은 셸 판정을 받는다(v35 21 — Monitor 는 Bash 와 같은 셸에서 명령을 돌려, 빠지면 모든 판정을 비켜 간다).
 * 목록은 팀 규칙(team-rules.mjs)의 SHELL_TOOLS 와 같다: Claude 의 Bash · Monitor, Codex 의 셸 도구들, agy 의 run_command · send_command_input
 */
const SHELL_TOOLS = new Set(['Bash', 'Monitor', 'shell', 'exec_command', 'local_shell', 'unified_exec', 'write_stdin', 'run_command', 'send_command_input'])
/** 셸 도구가 돌릴 글이 든 칸 — 팀 규칙의 shellCommand 와 같은 차례(agy 의 CommandLine 은 그 뒤에 더 본다) */
const SHELL_FIELDS = ['command', 'cmd', 'chars', 'input', 'CommandLine']
/** 배열로 준 명령(Codex 의 argv)은 셸 낱말로 따옴표를 쳐 잇는다 — 그냥 띄어 이으면 `bash -lc 'git push …'`의 -c 글이 낱말로 흩어져 셸에 넘긴 글로 보이지 않는다 */
const shellWord = (word) => {
  const text = String(word)
  return /^[\w@%+=:,./-]+$/.test(text) ? text : `'${text.replaceAll("'", "'\\''")}'`
}

/**
 * 한 호출의 판정(동기) — { decision: 'deny' | 'ask' | 'allow', reason, updatedInput? } 또는 null.
 * ctx: { root(프로젝트 뿌리), cwd(상대 경로를 푸는 곳), seat(자리 — seat() 의 결과. 없으면 Paseo 밖처럼 카드 권한 있음), rewrite(false 면 11번 다시 쓰기를 하지 않음) }.
 * 'allow' 는 11번(되풀이 검색을 .env 를 빼는 꼴로 다시 씀)에서만 낸다. 카드 권한에 따라 나뉘는 것은 7(기본 가지 커밋)과 13(설정 파일)뿐이고,
 * 물음을 막음으로 바꾸는 것(14 · 15 · 16)은 judge 가 한다
 */
export function decide(input, ctx = {}) {
  const toolInput = input?.tool_input ?? {}
  const root = ctx.root ?? input?.cwd ?? process.cwd()
  ctx = { ...ctx, root, cwd: ctx.cwd ?? input?.cwd ?? root }
  if (SHELL_TOOLS.has(input?.tool_name)) return decideShell(toolInput, ctx)
  switch (input?.tool_name) {
    case 'Read':
      return checkPath(toolInput.file_path, 'read', ctx)
    case 'Edit':
      return checkPath(toolInput.file_path, 'write', ctx, () => applyEdits(toolInput.file_path, [toolInput], ctx))
    case 'MultiEdit':
      return checkPath(toolInput.file_path, 'write', ctx, () => applyEdits(toolInput.file_path, Array.isArray(toolInput.edits) ? toolInput.edits : [], ctx))
    case 'Write':
      return checkPath(toolInput.file_path, 'write', ctx, () => String(toolInput.content ?? ''))
    case 'NotebookEdit':
      return checkPath(toolInput.notebook_path, 'write', ctx, () => String(toolInput.new_source ?? ''))
    case 'apply_patch':
      return checkPatch(typeof toolInput.command === 'string' ? toolInput.command : '', ctx)
    case 'Grep': {
      const target = typeof toolInput.path === 'string' ? toolInput.path : ''
      const glob = typeof toolInput.glob === 'string' ? toolInput.glob : ''
      if ((target && isSecretEnvPath(target, ctx)) || (glob && globMayMatchSecretEnv(glob))) {
        return { decision: 'deny', reason: REASON.env }
      }
      return null
    }
    default:
      return null
  }
}

/**
 * 셸 도구(SHELL_TOOLS)의 판정 — 명령 글을 꺼내 judgeCommand 로 본다. 11: 되풀이 검색 때문에만 막히는 단순한 줄은 .env 를 빼는 꼴로 다시 써서(rewriteSearch)
 * 처음부터 다시 판정하고, 통과면 'allow' + updatedInput(다른 칸은 그대로), 물음이 남으면 다시 쓴 명령으로 묻는다. 다시 쓰지 않는 곳: ctx.rewrite === false
 * (다시 쓴 명령을 넘기지 못하는 부름 — judge 가 정함), agy 자리, 배열로 준 명령
 */
function decideShell(toolInput, ctx) {
  const field = SHELL_FIELDS.find((key) => toolInput[key] !== undefined && toolInput[key] !== null) ?? 'command'
  const given = toolInput[field]
  const command = Array.isArray(given) ? given.map(shellWord).join(' ') : typeof given === 'string' ? given : given === undefined ? '' : String(given)
  const result = judgeCommand(command, ctx)
  if (result?.decision !== 'deny' || (result.reason !== REASON.grep && result.reason !== REASON.rg)) return result
  if (typeof given !== 'string' || ctx.rewrite === false || ctx.seat?.kind === 'agy') return result
  const rewritten = rewriteSearch(command)
  if (rewritten === null) return result
  const again = judgeCommand(rewritten, ctx)
  if (again?.decision === 'deny') return again
  const updatedInput = { ...toolInput, [field]: rewritten }
  // 훅의 allow 는 권한 확인 · 판정기를 건너뛴다 — 다시 쓴 줄이 검색과 읽기만 하는 거름(파이프)뿐일 때만 허락하고,
  // 다른 명령이 이어 붙은 줄(; && || · xargs rm · chmod …)은 막고 다시 쓴 꼴을 알린다(2026-10-18 반대 검토 G1 — R8)
  if (!searchOnly(rewritten)) return { decision: 'deny', reason: `${result.reason} 검색만 홀로 쓰면(읽기 거름 head · sort · wc · uniq … 만 이어서) 훅이 .env 를 빼는 꼴로 바꿔 돌립니다. 이 꼴로 다시: ${rewritten}` }
  return again === null ? { decision: 'allow', reason: REASON.rewrite, updatedInput } : { ...again, updatedInput }
}

/** 다시 쓴 검색 줄에 이어도 되는 읽기 거름 — 파일을 쓰거나 다른 명령을 돌리지 않는 것만(sort -o · --output 은 뺌) */
const SEARCH_FILTERS = new Set(['grep', 'egrep', 'fgrep', 'rg', 'head', 'tail', 'sort', 'wc', 'uniq', 'cut', 'tr', 'nl', 'column', 'fold'])
/** 파이프로만 이은 검색 · 읽기 거름 줄인가(따옴표 밖에 ; & || 줄바꿈 ` $( > < 가 없고, 명령마다 SEARCH_FILTERS) */
function searchOnly(command) {
  // 따옴표 안은 빼고 보고, 오류 출력 버리기(2>/dev/null)만 받는다
  const bare = String(command).replace(/'[^']*'/g, "''").replace(/"(?:[^"\\]|\\.)*"/g, '""').replace(/(^|\s)2>\s*\/dev\/null(?=\s|$)/g, '$1')
  if (/[;&\n\r`<>]|\|\||\$\(/.test(bare)) return false
  const parts = simpleCommands(command)
  return parts.length > 0 && parts.every(({ name, args }) => {
    const base = path.posix.basename(String(name))
    if (!SEARCH_FILTERS.has(base)) return false
    return !(base === 'sort' && args.some((a) => /^(-o|--output)/.test(a) || /^-[a-zA-Z]*o/.test(a)))
  })
}

/**
 * 명령 글 하나의 판정. 글자만 보는 판정(.env·1Password·키체인·DB 초기화·훅 우회)을 먼저 끝까지 돌리고 거부가 있으면 바로 낸다.
 * 기획 자료 판정은 파일 시스템(공유 드라이브)을 보는데, 드라이브가 늦어 훅 시간 제한(10초)을 넘기면
 * 같은 명령 줄의 거부까지 사라질 수 있어서다 (2026-10-07 jarvis 검토)
 */
function judgeCommand(command, ctx) {
  if (mentionsCheckRecord(command)) return { decision: 'deny', reason: REASON.checkRecordBash }
  const byText = checkBash(command, ctx, false)
  return byText?.decision === 'deny' ? byText : checkBash(command, ctx, true)
}

/**
 * 확장 자리에 주는 도구 — 명령 줄을 단순 명령({ name, args })으로 나눈다. 따옴표 · heredoc · 감싸는 명령(sudo · env · npx …)은 틀과 같게 풀고,
 * 큰따옴표 안과 따옴표 없는 heredoc 본문의 명령 치환도 넣는다
 */
const simpleCommandsMemo = new Map()
export function simpleCommands(command) {
  const text = String(command ?? '')
  if (!simpleCommandsMemo.has(text)) {
    const list = []
    // $'…' · $"…"를 푼 줄은 두 꼴로 나눈 명령을 모두 준다(splitModes) — 확장이 더 엄한 쪽을 보게
    for (const { segments, quotedBodies } of splitModes(text)) {
      resolveShellVars(segments)
      list.push(...segments.map(({ words }) => commandOf(words)).filter((c) => c.name !== '').map(({ name, args }) => ({ name, args })))
      for (const inner of quotedBodies) list.push(...simpleCommands(inner))
      for (const { expandingHeredocs } of segments) {
        for (const body of expandingHeredocs) for (const inner of heredocSubstitutions(body)) list.push(...simpleCommands(inner))
      }
    }
    simpleCommandsMemo.set(text, list)
  }
  return simpleCommandsMemo.get(text).map(({ name, args }) => ({ name, args: [...args] }))
}

/**
 * 프로젝트 전용 규칙(확장 자리, 2026-10-12) — 틀은 그대로 두고 `.claude/hooks/guard.local.mjs`가 있으면 같은 입력으로 불러 더 엄한 판정을 따른다
 * (deny > ask > 통과). 그 파일은 `export function decide(input, ctx)`를 내고 { decision: 'deny' | 'ask', reason } 또는 null을 돌려준다.
 * ctx는 { root, cwd, commands(명령 줄) → [{ name, args }] }. 틀의 판정을 풀 수는 없다. 틀 대조(tpl-guard)는 이 파일을 보지 않는다.
 * 확장이 깨져 판정하지 못하면(읽기 실패, decide 없음, 던짐) 프로젝트 규칙을 확인할 수 없으므로 묻는다 — 조용히 지나가지 않게
 */
async function withLocal(result, input, root) {
  const rank = (r) => (r?.decision === 'deny' ? 2 : r?.decision === 'ask' ? 1 : 0)
  // 틀이 명령을 다시 썼으면(11) 실제로 돌 명령(다시 쓴 것)을 확장에 준다. 확장이 물으면 다시 쓴 명령으로 묻는다
  const rewritten = result?.updatedInput ? { updatedInput: result.updatedInput } : {}
  const localInput = result?.updatedInput ? { ...input, tool_input: result.updatedInput } : input
  let extra
  try {
    const local = path.join(root, '.claude/hooks/guard.local.mjs')
    if (!existsSync(local)) return result
    const mod = await import(pathToFileURL(local).href)
    if (typeof mod.decide !== 'function') throw new Error('decide 함수를 내지 않습니다')
    extra = await mod.decide(localInput, { root, cwd: input.cwd || root, commands: simpleCommands })
  } catch (e) {
    const why = `${REASON.local} (${String(e?.message ?? e).split('\n')[0].slice(0, 200)})`
    return { decision: 'ask', reason: result?.decision === 'ask' ? `${result.reason} ${why}` : why, ...rewritten }
  }
  if (rank(extra) <= rank(result)) return result
  const reason = typeof extra.reason === 'string' && extra.reason !== '' ? extra.reason : '이 프로젝트의 가드 확장(guard.local.mjs) 규칙에 걸렸습니다.'
  return { decision: extra.decision, reason, ...(extra.decision === 'ask' ? rewritten : {}) }
}

// ---------- 자리(seat)와 카드 권한(cardRight) — v35 14 · 19 ----------
// 카드 권한 = 되돌릴 수 없는 일의 확인 창(권한 카드)을 띄울 수 있는 세션 — 대표님이 연 탭뿐이다. 팀 규칙(team-rules.mjs)의 cardRight 와 같은 뜻이고,
// 가드는 저장소 사본이라 바깥 파일을 불러오지 않고 안에 같은 함수를 둔다(같은 시험 자료로 견준다 — tests/guard.test.mjs)
const AGENT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const isAgentId = (id) => typeof id === 'string' && AGENT_ID.test(id)

/**
 * 카드 권한이 있는가 — id 가 Paseo 세션 꼴(UUID)이 아니면 Paseo 밖(대표님이 그 자리에 있는 터미널)이라 있음, 서브에이전트는 없음,
 * 그 밖에는 첫 inspect 기록(parentSeen)의 parent 가 비어 있을 때만(대표님이 연 탭) 있음. 기록이 없으면 없음
 */
export function cardRight({ id, subagent = false, parentSeen = null } = {}) {
  if (!isAgentId(id)) return true
  if (subagent) return false
  return !!parentSeen && !parentSeen.parent
}

/** 팀 훅이 그 세션을 처음 볼 때 `paseo agent inspect` 의 ParentAgentId 를 적어 둔 기록 { parent } — 꼴이 틀리면 없는 것으로(기록이 없으면 카드 권한 없음) */
function parentRecord(home, id) {
  try {
    const value = JSON.parse(readFileSync(path.join(home, '.config/ai-setting/state/parents', id), 'utf8'))
    if (value === null || typeof value !== 'object' || Array.isArray(value) || !Object.hasOwn(value, 'parent')) return null
    if (value.parent !== null && typeof value.parent !== 'string') return null
    return { parent: value.parent }
  } catch {
    return null
  }
}

/**
 * 기록이 없을 때만 보는 agent 파일(~/.paseo/agents/<폴더>/<ID>.json)의 labels['paseo.parent-agent-id'] — 파일이 없거나 깨졌거나 labels 가 없으면 undefined.
 * 그 파일에는 MCP 인증 머리가 있다: 읽자마자 parent 하나만 남기고, 나머지는 변수에 두지도 찍지도 않는다(오류 글도 버린다 — JSON 오류 글에 내용 조각이 든다)
 */
function agentParentLabel(home, id) {
  let dirs
  try {
    dirs = readdirSync(path.join(home, '.paseo/agents'))
  } catch {
    return undefined
  }
  for (const dir of dirs) {
    const file = path.join(home, '.paseo/agents', dir, `${id}.json`)
    if (!existsSync(file)) continue
    try {
      const labels = JSON.parse(readFileSync(file, 'utf8'))?.labels
      if (labels === null || typeof labels !== 'object' || Array.isArray(labels)) return undefined
      const parent = labels['paseo.parent-agent-id']
      return typeof parent === 'string' ? parent : null
    } catch {
      return undefined
    }
  }
  return undefined
}

/**
 * 이 호출의 자리 { kind, cardRight } — kind: 'agy'(env.SEAT === 'agy' — 카드 권한 없음) · 'out'(PASEO_AGENT_ID 가 UUID 꼴이 아님 — Paseo 밖) ·
 * 'sub'(훅 입력에 agent_id — Claude 서브에이전트) · 'member'(parent 있음 — 다른 세션이 연 탭, 창구가 세운 지휘 포함) · 'solo'(parent 비어 있음) · 'unknown'(기록 없음).
 * parents 기록이 있으면 그것만 본다(labels 는 세션이 update_agent 로 바꿀 수 있다 — K4). 없을 때만 agent 파일의 labels 로 kind 를 정하고 카드 권한은 주지 않는다.
 * role label 은 보지 않는다. 읽기만 하고 던지지 않는다(못 읽으면 'unknown')
 */
export function seat({ input = {}, env = process.env, home = os.homedir() } = {}) {
  try {
    if (env?.SEAT === 'agy') return { kind: 'agy', cardRight: false }
    const id = env?.PASEO_AGENT_ID
    if (!isAgentId(id)) return { kind: 'out', cardRight: true }
    // 전역 장치(정책 표 policy.json — 전환 때 생성기가 넣고 parents 기록을 쓰는 훅과 함께 온다)가 없으면 v34 처럼 물음은 물음으로 둔다:
    // 되돌리기 뒤에도 프로젝트 가드는 v35 로 남는데, 기록을 쓰는 훅이 없으면 모든 세션이 카드 없음이 되어 대표님 탭의 물음까지 막힌다(반대 검토 K9)
    if (!existsSync(path.join(home, '.agents/skills/ai-setting/policy/policy.json'))) return { kind: 'legacy', cardRight: true }
    if (input?.agent_id !== undefined && input.agent_id !== null && input.agent_id !== '') return { kind: 'sub', cardRight: false }
    const seen = parentRecord(home, id)
    if (seen) return { kind: seen.parent ? 'member' : 'solo', cardRight: cardRight({ id, parentSeen: seen }) }
    const parent = agentParentLabel(home, id)
    if (parent === undefined) return { kind: 'unknown', cardRight: false }
    return { kind: parent ? 'member' : 'solo', cardRight: false }
  } catch {
    return { kind: 'unknown', cardRight: false }
  }
}

/** 물음을 막음으로 바꿀 때 까닭 끝에 붙이는 글(14 · 15 · 16) — 팀원 · 서브 · Codex · bypass · agy */
const NOTE = {
  codexCard: 'Codex는 확인 창을 띄울 수 없어 막습니다. 꼭 해야 하면 Claude 지휘 탭에서 하거나 대표님이 직접 합니다.',
  codex: 'Codex는 확인 창을 띄울 수 없어 막습니다.',
  bypass: 'bypass 모드라 물을 수 없어 막습니다. 꼭 해야 하면 bypass를 끄고 다시 하세요.',
  agy: 'Antigravity(agy)는 확인 창을 띄울 수 없어 막습니다.',
  team: '이 탭은 확인 창을 띄우지 않습니다 — team.sh ask 로 결정 요청을 보내고 상관없는 일을 계속합니다.',
  sub: '이 탭은 확인 창을 띄우지 않습니다 — 부른 세션에 보고로 돌려줍니다.',
}

/**
 * 마지막 판정 — decide(틀) + guard.local(확장) 뒤에 물음을 받을 수 없는 곳이면 막음으로 바꾼다. main 과 정책 훅(easpera-hook 의 가드 다리)이 부른다.
 * 막음으로 바꾸는 곳: Codex(GUARD_CLIENT=codex — 훅의 물음을 받지 못하고 그대로 실행한다, codex-cli 0.153.4 실측), bypass 모드(Claude Code 가 훅의 물음을
 * 묻지 않고 허락한다, 2026-10-08 시험), agy(SEAT=agy 또는 AGY_GUARD_UNATTENDED=1), 카드 권한 없는 자리(팀원 · 서브에이전트 · 다른 세션이 연 탭 · 모름 — 창을 띄우지 않고
 * 결정 요청으로). 11번 다시 쓰기는 다시 쓴 명령을 넘길 수 있는 곳에서만 한다 — Claude · Codex 가 준 훅 입력(session_id 가 있음)이고 agy 가 아닐 때
 * (옛 agy 연결은 allow 를 넘기지 않아 다시 쓰면 원래 명령이 돈다)
 */
export async function judge(input, { root, cwd, env = process.env, home = os.homedir() } = {}) {
  const base = root ?? input?.cwd ?? process.cwd()
  const where = { root: base, cwd: cwd ?? input?.cwd ?? base }
  const place = seat({ input, env, home })
  const agy = env?.SEAT === 'agy' || (env?.AGY_GUARD_UNATTENDED !== undefined && env?.AGY_GUARD_UNATTENDED !== '')
  const rewrite = !agy && typeof input?.session_id === 'string' && input.session_id !== ''
  let result = decide(input, { ...where, seat: place, rewrite })
  // 프로젝트 전용 규칙(withLocal). 틀이 이미 막았으면 부르지 않는다 — 더 엄할 수 없고, 파일 시스템을 보기 전에 나온 거부를 그대로 둔다
  if (result?.decision !== 'deny') result = await withLocal(result, input ?? {}, where.root)
  if (result?.decision !== 'ask') return result
  const notes = []
  if (env?.GUARD_CLIENT === 'codex') notes.push(place.cardRight ? NOTE.codexCard : NOTE.codex)
  else if (input?.permission_mode === 'bypassPermissions') notes.push(NOTE.bypass)
  else if (env?.SEAT === 'agy' || env?.AGY_GUARD_UNATTENDED === '1') notes.push(NOTE.agy)
  if (!place.cardRight) notes.push(place.kind === 'sub' ? NOTE.sub : NOTE.team)
  return notes.length === 0 ? result : { decision: 'deny', reason: `${result.reason} ${notes.join(' ')}` }
}

/** 직접 실행했을 때만(훅) stdin 을 읽는다 — import 하면(정책 훅 · 시험) 읽지 않는다. 링크로 부른 경로도 실제 파일로 견준다 */
function runAsHook() {
  if (!process.argv[1]) return false
  const self = fileURLToPath(import.meta.url)
  try {
    return realpathSync(process.argv[1]) === realpathSync(self)
  } catch {
    return path.resolve(process.argv[1]) === self
  }
}

async function main() {
  const raw = readFileSync(0, 'utf8')
  let result
  try {
    const input = JSON.parse(raw)
    const root = process.env.CLAUDE_PROJECT_DIR || input.cwd || process.cwd()
    result = await judge(input, { root, cwd: input.cwd || root })
  } catch {
    // 판정을 못 했다. 위험한 냄새가 나는 호출만 막고 나머지는 평소 흐름에 맡긴다
    result = /\.[eE][nN][vV]|_private|(^|[\/\s"'=@])_core(\/|$|[\s"'])|CloudStorage\/GoogleDrive-/.test(raw) ? { decision: 'deny', reason: REASON.internal } : null
  }
  if (result) {
    const output = { hookEventName: 'PreToolUse', permissionDecision: result.decision, permissionDecisionReason: result.reason }
    if (result.updatedInput && result.decision !== 'deny') output.updatedInput = result.updatedInput
    process.stdout.write(JSON.stringify({ hookSpecificOutput: output }))
  }
}

if (runAsHook()) await main()
