#!/usr/bin/env python3
"""커밋된 시크릿 차단 게이트.

2026-08-25 전수 스윕(6호스트·82레포)에서 **살아있는 시크릿 4건**이 커밋된 채 발견됐다:

  mote-modules  static/AuthKey_[KeyID].p8   Apple 개인키    221일 (dev 에서 인터넷 공개)
  mote-cloud    application-{dev,prod}.yml  EC 배포키(쓰기)  154일 (지금도 유효)
  mote-dev      task-infra-...-01.md        GitHub PAT      100일 (지금도 유효)
  allcl_api...  ...firebase-adminsdk.json   Firebase Admin  약 4년

넷 다 «커밋 시점에 막을 방법이 없어서» 들어갔고, 100일~4년간 아무도 몰랐다.
조직 플랜이 team 이라 GitHub 네이티브 시크릿 스캐닝(GHAS)은 쓸 수 없다.

★판정 원칙 — 이 게이트는 절대 fail-open 하지 않는다.
  base 를 못 찾거나 diff 를 못 읽으면 «시크릿 없음»이 아니라 **rc=2 로 실패**시킨다.
  «0건»은 스캐너 고장일 수도 있다. --self-test 가 그 위장을 막는 대조군이다.
"""
from __future__ import annotations
import argparse, os, re, subprocess, sys

# 구조가 확실한 패턴만. 범용 엔트로피 검사는 오탐이 많아 넣지 않는다.
RULES: list[tuple[str, re.Pattern]] = [
    ("GitHub token",       re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}")),
    ("AWS access key",     re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Slack token",        re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("Anthropic key",      re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("OpenAI key",         re.compile(r"sk-proj-[A-Za-z0-9_-]{20,}")),
    ("Google API key",     re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("GitLab PAT",         re.compile(r"glpat-[A-Za-z0-9_-]{15,}")),
    ("private key block",  re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]

# 면제는 **경로로만** 판단한다(내용 기반 면제는 진짜 유출까지 놓친다).
ALLOW_PATH = re.compile(
    r"(^|/)(test|tests|__tests__)/"
    r"|\.(test|spec)\.[a-z]+$"
    r"|(^|/)[^/]*\.example(\.[a-z]+)?$"
    r"|(^|/)detekt-baseline\.xml$"
    # ★이 파일 자신(패턴 정의·self-test 픽스처). 레포마다 위치가 다르므로 파일명으로 잡는다 —
    #   mote-dev 는 ADR-001 때문에 .github/actions/secret-scan/ 아래에 둔다.
    r"|(^|/)guard_secret_scan\.py$"
)
# 한 줄만 면제. 사유를 반드시 적게 해서 남용을 막는다.
INLINE_ALLOW = re.compile(r"secret-scan:allow\s+\S")


def sh(*args: str) -> str:
    r = subprocess.run(args, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"{' '.join(args)} rc={r.returncode}: {r.stderr.strip()[:300]}")
    return r.stdout


def match_line(path: str, line: str) -> str | None:
    """규칙명 또는 None. 시크릿 본문은 반환하지 않는다."""
    if ALLOW_PATH.search(path) or INLINE_ALLOW.search(line):
        return None
    for name, pat in RULES:
        if pat.search(line):
            return name
    return None


def scan_text(path: str, text: str) -> list[tuple[int, str]]:
    return [(i, n) for i, ln in enumerate(text.splitlines(), 1)
            if (n := match_line(path, ln))]


def added_lines(base: str, head: str) -> dict[str, list[tuple[int, str]]]:
    """PR 에서 **추가된 줄**만. 기존 파일의 오래된 시크릿까지 잡으면 아무 PR 도 못 통과한다."""
    diff = sh("git", "diff", "--unified=0", "--no-color", f"{base}...{head}")
    files: dict[str, list[tuple[int, str]]] = {}
    cur, ln = None, 0
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            cur = line[6:]; files.setdefault(cur, [])
        elif line.startswith("@@"):
            m = re.search(r"\+(\d+)", line)
            ln = int(m.group(1)) if m else 0
        elif line.startswith("+") and not line.startswith("+++") and cur is not None:
            files[cur].append((ln, line[1:])); ln += 1
    return files


def report(hits: list[tuple[str, int, str]], mode: str) -> None:
    """★시크릿 본문은 절대 출력하지 않는다 — CI 로그가 새 유출 경로가 된다."""
    where = "이 PR 에서 추가됩니다" if mode == "diff" else "레포에 남아 있습니다"
    print("", file=sys.stderr)
    print(f"🔴 시크릿 {len(hits)}건이 {where}.", file=sys.stderr)
    for path, line, rule in hits:
        print(f"   {path}:{line}  — {rule}", file=sys.stderr)
    print("""
해야 할 일:
  1. 해당 줄을 제거하고 값을 환경변수·Spring Cloud Config 로 옮긴다
  2. ★이미 push 했다면 그 시크릿은 유출된 것이다 — 반드시 폐기·재발급한다
     (파일을 지워도 히스토리·포크·CI 캐시에 남는다)
  3. 테스트 픽스처 등 진짜 예외라면 그 줄에 `secret-scan:allow <사유>` 를 단다""",
          file=sys.stderr)


def self_test() -> int:
    """대조군 — 잡아야 할 것을 잡고, 면제해야 할 것을 면제하는지 증명한다.
    이 스텝 없이 «0건»을 신뢰하면 스캐너가 고장나도 초록으로 통과한다."""
    must_catch = [
        ("a.yml", "token: ghp_" + "A" * 36),
        ("b.yml", "aws: AKIA" + "B" * 16),
        ("c.json", '"private_key": "-----BEGIN PRIVATE KEY-----\\nMII..."'),
        ("d.yml", "  private-key: -----BEGIN EC PRIVATE KEY-----"),
        ("e.env", "SLACK_BOT_TOKEN=xoxb-1234567890-abcdefghij"),
        ("f/g/h.properties", "key=AIza" + "C" * 35),
    ]
    must_ignore = [
        ("src/tests/fixture.py", "TOKEN = 'ghp_" + "A" * 36 + "'"),
        ("config.example.env", "TOKEN=ghp_" + "A" * 36),
        ("real.yml", "token: ghp_" + "A" * 36 + "  # secret-scan:allow 문서 예시"),
        ("plain.yml", "name: application-adapter-allcl"),
        ("short.yml", "id: ghp_short"),
        ("adapter-allcl/detekt-baseline.xml", "<ID>x ghp_" + "A" * 36 + "</ID>"),
    ]
    bad = 0
    for path, text in must_catch:
        if not scan_text(path, text):
            print(f"  ❌ 못 잡음: {path}", file=sys.stderr); bad += 1
    for path, text in must_ignore:
        if scan_text(path, text):
            print(f"  ❌ 오탐: {path}", file=sys.stderr); bad += 1
    if bad:
        print(f"🔴 self-test 실패 {bad}건 — 스캐너가 고장났다. 판정을 신뢰할 수 없다.", file=sys.stderr)
        return 1
    print(f"✅ self-test 통과 (탐지 {len(must_catch)}건 / 면제 {len(must_ignore)}건)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--all", action="store_true", help="추가분이 아니라 추적 파일 전체를 검사")
    a = ap.parse_args()
    if a.self_test:
        return self_test()

    hits: list[tuple[str, int, str]] = []
    if a.all:
        scanned = 0
        for p in sh("git", "ls-files").splitlines():
            try:
                text = open(p, encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            scanned += 1
            hits += [(p, ln, rule) for ln, rule in scan_text(p, text)]
        print(f"검사 대상: 추적 파일 {scanned}개")
        mode = "all"
    else:
        def resolve(*cands: str) -> str | None:
            for ref in cands:
                if not ref:
                    continue
                try:
                    sh("git", "rev-parse", "--verify", f"{ref}^{{commit}}")
                    return ref
                except RuntimeError:
                    continue
            return None

        base_env = os.environ.get("GITHUB_BASE_REF") or "develop"
        base = resolve(f"origin/{base_env}", base_env)
        if base is None:
            # ★검사하지 못한 것을 «통과»로 보고하지 않는다.
            print(f"🔴 base ref '{base_env}' 를 찾을 수 없다 — 검사 못 했으므로 통과시키지 않는다.",
                  file=sys.stderr)
            return 2

        # ★actions/checkout 은 PR 을 detached HEAD 로 받는다 — 브랜치명 ref 가 로컬에 없다.
        #   그래서 GITHUB_HEAD_REF 를 그대로 쓰면 CI 에서만 rc=2 로 죽는다(2026-08-25 실제 발생).
        #   HEAD 를 마지막 폴백으로 둔다.
        head_env = os.environ.get("GITHUB_HEAD_REF")
        head = resolve(head_env, f"origin/{head_env}" if head_env else None, "HEAD")
        if head is None:
            print("🔴 head ref 를 찾을 수 없다 — 검사 못 했으므로 통과시키지 않는다.", file=sys.stderr)
            return 2
        try:
            files = added_lines(base, head)
        except RuntimeError as e:
            print(f"🔴 diff 계산 실패 — 검사 못 했으므로 통과시키지 않는다: {e}", file=sys.stderr)
            return 2
        total = sum(len(v) for v in files.values())
        print(f"검사 대상: 변경 파일 {len(files)}개 · 추가된 줄 {total}개 (base={base})")
        for path, lines in files.items():
            hits += [(path, ln, rule) for ln, text in lines
                     if (rule := match_line(path, text))]
        mode = "diff"

    if hits:
        report(hits, mode)
        return 1
    print("✅ 시크릿 패턴 없음")
    return 0


if __name__ == "__main__":
    sys.exit(main())
