#!/usr/bin/env node
// PostToolUse 훅 (Bash) — 명령 출력에 비밀값으로 보이는 문자열이 찍혔는지 gitleaks로 본다.
// project-setting 스킬의 틀(templates/claude-guard)에서 왔고, jarvis 프로젝트의 훅을 바탕으로 했다.
//
// 가드 훅(guard.mjs)은 명령 문자열만 보므로, 스크립트가 안에서 값을 찍는 것은 막지 못한다.
// 출력은 이미 대화 기록에 들어갔으니 이 훅도 막을 수는 없다 — 대신 바로 알린다:
//   사람에게는 systemMessage(어떤 종류의 값인지, 키 교체 검토),
//   에이전트에게는 decision: block + reason(값을 다시 출력하거나 옮겨 적지 말 것).
// 값 자체와 명령 문자열은 이 훅의 출력 어디에도 싣지 않는다 (공통 규칙 3).
//
// 로컬 Supabase의 기본 키(supabase status 값)는 공개된 개발용 값이라 제외한다.
// gitleaks가 없으면 조용히 넘어간다.
// 시험: project-setting 스킬의 tests/output-scan.test.mjs (node --test)

import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { parseEnv } from 'node:util'

const MAX_CHARS = 2_000_000

/** tool_response 안의 문자열을 모두 모은다 — stdout·stderr의 모양이 바뀌어도 놓치지 않게 */
function collectText(value, out = []) {
  if (typeof value === 'string') out.push(value)
  else if (Array.isArray(value)) for (const item of value) collectText(item, out)
  else if (value && typeof value === 'object') for (const item of Object.values(value)) collectText(item, out)
  return out
}

/** gitleaks stdin의 JSON 결과. gitleaks가 없거나 실패하면 빈 목록 */
function scan(text) {
  const result = spawnSync(
    'gitleaks',
    ['stdin', '--no-banner', '--log-level', 'error', '--report-format', 'json', '--report-path', '-', '--exit-code', '0'],
    { input: text, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024, timeout: 20_000 },
  )
  if (result.error || result.status !== 0) return []
  try {
    const findings = JSON.parse(result.stdout || '[]')
    return Array.isArray(findings) ? findings : []
  } catch {
    return []
  }
}

/** 로컬 Supabase의 공개 개발용 값 — 찾은 것이 있을 때만 한 번 조회한다. Supabase를 쓰지 않으면 빈 목록 */
function localDevValues() {
  const result = spawnSync('supabase', ['status', '-o', 'env'], { encoding: 'utf8', timeout: 10_000 })
  if (result.error || result.status !== 0) return []
  return Object.values(parseEnv(result.stdout ?? '')).filter((value) => typeof value === 'string' && value.length >= 16)
}

const input = JSON.parse(readFileSync(0, 'utf8'))
const text = collectText(input.tool_response).join('\n').slice(0, MAX_CHARS)
if (text.trim() === '') process.exit(0)

let findings = scan(text)
if (findings.length > 0) {
  const local = localDevValues()
  findings = findings.filter(
    (finding) => !local.some((value) => value.includes(finding.Secret) || String(finding.Secret).includes(value)),
  )
}
if (findings.length === 0) process.exit(0)

const rules = [...new Set(findings.map((finding) => finding.RuleID))].join(', ')
process.stdout.write(
  JSON.stringify({
    decision: 'block',
    reason:
      `직전 명령의 출력에 비밀값으로 보이는 문자열 ${findings.length}개가 있다 (gitleaks 규칙: ${rules}). ` +
      '출력은 이미 대화 기록에 남았다. 값을 다시 출력하거나 옮겨 적지 말고 같은 명령도 다시 실행하지 않는다. ' +
      '사용자에게 어떤 종류의 값인지(규칙 이름) 알리고 그 키를 교체할지 묻는다 (공통 규칙 3).',
    systemMessage: `⚠️ 명령 출력에 비밀값으로 보이는 것이 찍혔습니다 (gitleaks: ${rules}). 대화 기록에 남았으니 해당 키 교체를 검토하세요.`,
  }),
)
