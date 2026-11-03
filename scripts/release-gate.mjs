#!/usr/bin/env node
// release-gate.mjs — 公開・配布・リリースの「実動作の関門」。出す物そのものを実機・本番相当で主要機能まで動かした記録が無ければ止める。
// 仮想環境の検証だけで「Macで動作検証済み」と書かない・実機で通していない版を出さないための検査（依存ゼロ・Node 18+）。
// 台帳は各リポジトリの docs/security/release-verification.json（CI・Vercelのビルドから読めるようリポ内に置く）:
//   { "product", "channels": { "<経路>": { "required": [ { "env": "macOS", "steps": ["real-cut","restore"] } ] } },
//     "records": [ { "artifact": "<commit SHA（メモ）>", "content_id": "content:<id コマンドの出力>", "channel", "env", "tier": 1|2|3, "exercised": [..], "built_by", "by", "at", "evidence": "<相対パス>", "evidence_sha256" } ] }
// 段: 1=仮想環境で確認 / 2=実機で一部まで確認（観測まで） / 3=実機で実動作まで確認。合格に数えるのは3だけ。手元・仮想環境は1。
// 使い方:
//   node scripts/release-gate.mjs check --channel <経路> --artifact <tag|commit> [--ledger <path>]   不合格 exit 1（足りない物・必要な手を出す）
//   node scripts/release-gate.mjs id [<ref>]                                                         記録に書く content_id（版の指紋）を出す
//   node scripts/release-gate.mjs vercel-ignore [--channel vercel-prod]                              Vercelの ignoreCommand 用。続行は exit 7、それ以外（不合格・異常）はすべてビルド停止
//   node scripts/release-gate.mjs claims <files...> [--ledger <path>]                                公開文面の「検証済み」と台帳のずれを検出（不合格 exit 1）
//   node scripts/release-gate.mjs --selftest                                                         合格・不合格の自己検査
// 限界: 台帳の記録が本物かは「証拠ファイルのSHA-256一致」と「作った人≠確かめた人」までしか機械では見られない。証拠の中身の真偽は作った人と別の確認者が見る。
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';

const TIER_LABEL = { 1: '仮想環境で確認', 2: '実機で一部まで確認', 3: '実機で実動作まで確認' };
const PROCEED = 7; // vercel-ignore: ビルド続行を表す専用コード（Vercelの「1=続行」には後段のshellで変換する）
const STRONG = /検証済|動作確認済|実機で(の)?(動作を?)?(確認|検証)|実動作まで確認|[Vv]erified (on|with)|[Tt]ested on/;
const ENV_WORDS = /\bmac(os)?\b|linux|windows|iphone|\bios\b|android|実機|本番/i;
const ENV_NAMES = ['macOS', 'Linux', 'Windows', 'iPhone', 'Android'];
const HW = /実機|real (mac|hardware|machine)/i; // 版と並べて書くと「その版を実機で確かめた」と読める語
const UNMEASURED = /実測していな|実測していません|未測定|not measured|unmeasured/i;
const VER = /\bv\d+\.\d+\.\d+\b/;

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');
const git = (cwd, ...a) => execFileSync('git', a, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();

function loadLedger(p) {
  const l = JSON.parse(fs.readFileSync(p, 'utf8'));
  if (!l.product || typeof l.channels !== 'object' || !Array.isArray(l.records)) throw new Error('台帳の形が不正（product/channels/records）');
  return l;
}

// 記録1件の検査。問題があれば文字列、無ければ null。型も検査する（空配列・文字列・オブジェクトで通さない）。
const isStr = (x) => typeof x === 'string' && x.trim() !== '';
function recordProblem(r, req, ledgerDir, forRelease = true) {
  // 記録を作った側が「これは公開許可には使えない」と判断した場合（例：実行されたコードの版が
  // 実測できていない）、その記録では**公開を**通さない。散文の note ではなく機械が読む印で判定する。
  // 印が無い記録は従来どおり（既定＝使える）。
  // 文面の照合（forRelease=false）には効かせない：印の意味は「この版を出してよい根拠にしない」で、
  // 「実機で実動作まで通した事実が無い」ではないため。
  if (forRelease && r.usable_for_release === false) return `この記録は公開許可に使えないと台帳に書かれている${isStr(r.unusable_reason) ? `（${r.unusable_reason}）` : ''}`;
  if (r.tier !== 3) return `記録は「${TIER_LABEL[r.tier] || '段不明'}」止まり。合格は「${TIER_LABEL[3]}」のみ`;
  if (!Array.isArray(r.exercised) || !r.exercised.every(isStr)) return '実施した手順の記録の形が不正';
  const miss = req.steps.filter((x) => !r.exercised.includes(x));
  if (miss.length) return `実動作の確認に必要な手順が未実施: ${miss.join(', ')}`;
  if (!isStr(r.by) || !isStr(r.built_by) || r.by.trim().toLowerCase().replace(/[\s_-]+/g, '') === r.built_by.trim().toLowerCase().replace(/[\s_-]+/g, '')) return '確かめた担当が作った担当と同じ（または未記入）。別の担当の確認が要る';
  if (!isStr(r.at) || Number.isNaN(Date.parse(r.at))) return '確認した日付が無い・不正';
  if (!isStr(r.evidence) || !isStr(r.evidence_sha256)) return '証拠ファイルの指定が無い';
  // 証拠は docs/security/evidence/ の中の通常ファイルだけ（スクリプト自身・リンク経由の外部ファイルを証拠にできない）
  let evDir, ep;
  try { evDir = fs.realpathSync(path.resolve(ledgerDir, 'evidence')) + path.sep; ep = fs.realpathSync(path.resolve(ledgerDir, r.evidence)); } catch { return `証拠ファイルが docs/security/evidence/ に見つからない: ${r.evidence}`; }
  if (!ep.startsWith(evDir) || !fs.statSync(ep).isFile()) return `証拠ファイルが docs/security/evidence/ に見つからない: ${r.evidence}`;
  if (sha256(fs.readFileSync(ep)) !== r.evidence_sha256) return `証拠ファイルが記録時から変わっている: ${r.evidence}`;
  return null;
}

// 判定本体。戻り値: { ok, problems:[{env,what,who}] }。要件ごとに集計する（別の要件の合格で他の要件の不合格を消さない）。
export function evaluate(ledger, channel, commit, ledgerDir) {
  const ch = ledger.channels[channel];
  const reqs = ch && Array.isArray(ch.required) ? ch.required : [];
  const bad = (what, who = '製品担当（台帳の required を定義する）') => ({ ok: false, problems: [{ env: '-', what, who }] });
  if (reqs.length === 0) return bad(`経路「${channel}」の必須環境が台帳に無い`);
  if (!reqs.every((q) => isStr(q.env) && Array.isArray(q.steps) && q.steps.length > 0 && q.steps.every(isStr))) return bad('必須環境・手順の定義が不正（手順が空など）');
  if (new Set(reqs.map((q) => q.env)).size !== reqs.length) return bad('同じ環境の必須定義が重複している');
  if (!/^content:[0-9a-f]{64}$/.test(commit || '')) return bad('版の指紋（content:…）を特定できない', '版の指定');
  const problems = [];
  for (const req of reqs) {
    const recs = ledger.records.filter((r) => r && r.channel === channel && r.content_id === commit && r.env === req.env);
    if (recs.length === 0) { problems.push({ env: req.env, what: `この版（${commit.slice(8, 15)}）を ${req.env} の実環境で動かした記録が無い`, who: `${req.env} の実機（または本番相当）を持つ人と、作った側と別の確認者` }); continue; }
    const results = recs.map((r) => recordProblem(r, req, ledgerDir));
    if (results.some((x) => x === null)) continue; // この要件は合格
    for (const w of new Set(results)) problems.push({ env: req.env, what: w, who: `${req.env} の実機で実動作まで通す人／作った側と別の確認者` });
  }
  return { ok: problems.length === 0, problems };
}

// 文面の照合に使える記録＝その環境の要件を満たす記録（版・経路は問わないが、型・別の担当・証拠一致は evaluate と同じ検査を通す）
// version を渡すと、artifact がその版で始まり、かつ公開許可に使える記録だけを数える（版付きの主張にはその版の証拠を要求する）
function provenEnvs(ledger, ledgerDir, version = null) {
  const out = new Set();
  for (const r of ledger.records) {
    if (!r || !isStr(r.env) || !isStr(r.channel)) continue;
    if (version && !(isStr(r.artifact) && r.artifact.trim().split(/[\s(]/)[0] === version)) continue;
    const req = (ledger.channels[r.channel]?.required || []).find((q) => q.env === r.env);
    if (req && recordProblem(r, req, ledgerDir, version !== null) === null) out.add(r.env);
  }
  return out;
}

function card(product, channel, commit, problems) {
  const need = problems.map((p) => `${p.env}: ${p.what}（要る手: ${p.who}）`).join(' ／ ');
  return `RELEASE_BLOCKED: 【${product}】${channel} 版 ${commit.slice(0, 7)} は実機での動作確認の記録が無いため出せない。実機で確認して記録を足すまで公開しない（文面は「仮想環境で確認」「実機で一部まで確認」の段で書く）。不足: ${need}`.slice(0, 900);
}

// 版の指紋: 台帳フォルダ（docs/security/）を除く全ファイルの (mode, blob, path) 一覧のSHA-256。台帳に記録を足してもコミットSHAは変わるが、この指紋は変わらない
// ＝記録が自分の版を指せる。履歴が浅いクローン（Vercel等）でも計算できる。
export function contentId(cwd, commit) {
  const out = execFileSync('git', ['ls-tree', '-r', '-z', commit], { cwd, encoding: 'utf8', maxBuffer: 1 << 28 });
  return 'content:' + sha256(out.split('\0').filter((l) => l && !l.split('\t')[1].startsWith('docs/security/')).sort().join('\n'));
}

function resolveCommit(cwd, ref) {
  try { return git(cwd, 'rev-parse', `${ref}^{commit}`); } catch { return null; }
}

const stopCard = (o, what) => { console.error(`✖ ${what}`); console.error('  ' + card('(台帳を読む前に停止)', o.channel || '-', String(o.artifact || 'HEAD'), [{ env: '-', what, who: '版・台帳の指定を直せる人' }])); return 1; };

function cmdCheck(args) {
  const o = parseArgs(args);
  try { return cmdCheckInner(o); } catch (e) { return stopCard(o, `関門の実行に失敗（通さない）: ${e.message}`); }
}

function cmdCheckInner(o) {
  const ledgerPath = path.resolve(o.ledger || 'docs/security/release-verification.json');
  const commit = resolveCommit(process.cwd(), o.artifact || 'HEAD');
  if (!commit) return stopCard(o, `版を特定できない: ${o.artifact}`);
  if (commit === resolveCommit(process.cwd(), 'HEAD') && git(process.cwd(), 'status', '--porcelain') !== '') return stopCard(o, '未コミットの変更がある（確かめたコミットと出す物がずれる）。清浄な作業ツリーで実行する');
  const ledger = loadLedger(ledgerPath);
  const cid = contentId(process.cwd(), commit);
  const r = evaluate(ledger, o.channel, cid, path.dirname(ledgerPath));
  if (r.ok) { console.log(`✔ 実動作の関門 合格: ${ledger.product} / ${o.channel} / ${commit.slice(0, 7)} / ${cid}`); return 0; }
  console.error(`✖ 実動作の関門 不合格: ${ledger.product} / ${o.channel} / ${commit.slice(0, 7)} / ${cid}（この版は出せません）`);
  for (const p of r.problems) console.error(`  - [${p.env}] ${p.what} → 要る手: ${p.who}`);
  console.error('  次の手（止めたまま黙らない）:');
  console.error('  ' + card(ledger.product, o.channel, commit, r.problems));
  console.error(`  記録を足す時の content_id: ${cid}`);
  return 1;
}

// Vercel: 続行=PROCEED、それ以外はすべて停止。呼び出し側 `node ...; test $? -ne 7` で「7→1(続行)／他→0(停止)」に変換する＝異常終了でも止まる。
function cmdVercelIgnore(args) {
  const o = parseArgs(args);
  const venv = process.env.VERCEL_ENV || 'production';
  if (venv === 'preview' || venv === 'development') return PROCEED; // 公開物ではない。未知の値・未設定は本番扱い（停止側）
  const commit = resolveCommit(process.cwd(), 'HEAD'); // 作業ツリーのHEAD＝今からビルドする物（環境変数のSHAは使わない）
  const ledgerPath = path.resolve(o.ledger || 'docs/security/release-verification.json');
  try {
    const r = evaluate(loadLedger(ledgerPath), o.channel || 'vercel-prod', contentId(process.cwd(), commit), path.dirname(ledgerPath));
    if (r.ok) return PROCEED;
    for (const p of r.problems) console.error(`✖ 本番反映を停止 [${p.env}] ${p.what} → 要る手: ${p.who}`);
  } catch (e) { console.error(`✖ 本番反映を停止（台帳を読めない: ${e.message}）`); }
  return 0;
}

// 公開文面の照合: 強い表記（検証済み等）＋環境語の行は、その環境に3段目の記録があるときだけ許す。
// 文を。 . ; で分け、さらに「主張を言い終えた節」の後の読点でだけ分ける（「Mac は検証済み、Linux は未実施」は分け、「Mac、Linux は検証済み」は分けない）
function splitClaims(line) {
  const out = [];
  for (const sent of line.split(/(?<=[。;]|\.(?!\d))\s*/)) { // 版番号（v0.13.0）の中の点では切らない
    let cur = '';
    for (const part of sent.split(/(?<=、)/)) { cur += part; if (STRONG.test(cur)) { out.push(cur); cur = ''; } }
    if (cur) out.push(cur);
  }
  return out;
}

export function scanClaims(text, file, ledger, ledgerDir) {
  const tier3Envs = provenEnvs(ledger, ledgerDir);
  text = text.replace(/<[^>]+>/g, '');   // HTMLタグで語を割られても拾う
  const out = [];
  // 1行に「Macは検証済み。Linuxは未実施」と並ぶので、文（。 . ）単位で判定する
  text.split('\n').forEach((fullLine, i) => splitClaims(fullLine).forEach((line) => {
    const ver = (line.match(VER) || [])[0];
    const hwVersionClaim = ver && HW.test(line) && !UNMEASURED.test(line);
    if (!hwVersionClaim && (!STRONG.test(line) || !ENV_WORDS.test(line))) return;
    // 「未検証」「検証済みではない」の否定文脈は強い表記として数えない
    if (/依頼|してください|検証済み(では|と(は)?)ない|済みとは数えない|untested/.test(line) || /(virtual|仮想|runner|ランナー)[^。.]{0,60}(検証済|tested|verified)|(tested on|verified (on|with))[^。.]{0,20}(github|virtual|仮想)/i.test(line)) return;
    const envs = ENV_NAMES.filter((e) => new RegExp(e === 'macOS' ? '\\bmac(os)?\\b' : e, 'i').test(line));
    const proven = ver ? provenEnvs(ledger, ledgerDir, ver) : tier3Envs;
    if (envs.length === 0 || !envs.every((e) => proven.has(e))) out.push({ file, line: i + 1, text: line.trim().slice(0, 160), envs: envs.length ? envs : ['(環境不明)'] });
  }));
  return out;
}

function cmdClaims(args) {
  const o = parseArgs(args);
  const ledgerPath = path.resolve(o.ledger || 'docs/security/release-verification.json');
  const ledger = loadLedger(ledgerPath);
  if (o._.length === 0) { console.error('✖ 検査する公開文面が指定されていない（対象ゼロで合格にしない）'); return 1; }
  const hits = o._.flatMap((f) => scanClaims(fs.readFileSync(f, 'utf8'), f, ledger, path.dirname(ledgerPath)));
  if (!hits.length) { console.log('✔ 公開文面の表記と台帳にずれなし'); return 0; }
  console.error('✖ 「検証済み」系の表記に、台帳の「実機で実動作まで確認」の記録が無い（3段表記に直す）:');
  for (const h of hits) console.error(`  ${h.file}:${h.line} [${h.envs.join(',')}] ${h.text}`);
  return 1;
}

function parseArgs(a) {
  const o = { _: [] };
  for (let i = 0; i < a.length; i++) { if (a[i].startsWith('--')) o[a[i].slice(2)] = a[++i]; else o._.push(a[i]); }
  return o;
}

function selftest() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rg-'));
  const dir = path.join(tmp, 'docs', 'security'); fs.mkdirSync(dir, { recursive: true });
  fs.mkdirSync(path.join(dir, 'evidence')); const ev = path.join(dir, 'evidence', 'ev.txt'); fs.writeFileSync(ev, 'real run log');
  const C = 'content:' + 'a'.repeat(64);
  const rec = (x = {}) => ({ artifact: 'x', content_id: C, channel: 'git-tag', env: 'macOS', tier: 3, exercised: ['real-cut', 'restore'], built_by: 'maker', by: 'verifier', at: '2026-10-16', evidence: 'evidence/ev.txt', evidence_sha256: sha256(fs.readFileSync(ev)), ...x });
  const L = (records) => ({ product: 't', channels: { 'git-tag': { required: [{ env: 'macOS', steps: ['real-cut', 'restore'] }] } }, records });
  const cases = [
    ['記録なし→止まる', L([]), false], ['3段・別の担当・証拠一致→通る', L([rec()]), true],
    ['仮想環境(1段)→止まる', L([rec({ tier: 1 })]), false], ['実機で観測まで(2段)→止まる', L([rec({ tier: 2 })]), false],
    ['別の版の記録→止まる', L([rec({ content_id: 'content:' + 'b'.repeat(64) })]), false], ['別の環境の記録→止まる', L([rec({ env: 'Linux' })]), false],
    ['手順不足(restore無し)→止まる', L([rec({ exercised: ['real-cut'] })]), false], ['作った人=確かめた人→止まる', L([rec({ by: 'maker' })]), false],
    ['証拠が改変→止まる', L([rec({ evidence_sha256: '0'.repeat(64) })]), false], ['証拠ファイル無し→止まる', L([rec({ evidence: 'evidence/nope.txt' })]), false],
    ['証拠パスが台帳外(../)→止まる', L([rec({ evidence: '../../../../../etc/hosts' })]), false], ['証拠がevidence/の外(スクリプト自身)→止まる', L([rec({ evidence: '../../../scripts/release-gate.mjs', evidence_sha256: sha256(fs.readFileSync(new URL(import.meta.url))) })]), false],
    ['手順の文字列偽装→止まる', L([rec({ exercised: 'NOT real-cut; NOT restore' })]), false], ['担当がオブジェクト→止まる', L([rec({ by: { id: 's' }, built_by: { id: 's' } })]), false],
    ['日付なし→止まる', L([rec({ at: undefined })]), false], ['tierが文字列"3"→止まる', L([rec({ tier: '3' })]), false],
    ['不合格の後に合格記録→通る', L([rec({ tier: 2 }), rec()]), true],
    ['公開許可に使えない印つき→止まる', L([rec({ usable_for_release: false })]), false],
    // 印は公開許可にだけ効く。文面の照合（下の chk）では効かせない＝3段表記を落とさない
    ['印がtrue→通る', L([rec({ usable_for_release: true })]), true],
    ['使えない記録の後に使える記録→通る', L([rec({ usable_for_release: false }), rec()]), true],
  ];
  let bad = 0;
  const chk = (name, got, want) => { const ok = got === want; if (!ok) bad++; console.log(`${ok ? '✔' : '✖'} ${name}`); };
  for (const [n, l, want] of cases) chk(n, evaluate(l, 'git-tag', C, dir).ok, want);
  const weak = L([rec({ exercised: [] })]); weak.channels['git-tag'].required[0].steps = [];
  chk('必須手順が空の定義→止まる', evaluate(weak, 'git-tag', C, dir).ok, false);
  const dup = L([rec({ exercised: ['restore'] })]); dup.channels['git-tag'].required = [{ env: 'macOS', steps: ['real-cut', 'restore'] }, { env: 'macOS', steps: ['restore'] }];
  chk('同じ環境の必須定義が重複(後ろで前を消す)→止まる', evaluate(dup, 'git-tag', C, dir).ok, false);
  chk('版がSHAでない→止まる', evaluate(L([rec()]), 'git-tag', 'v1.0', dir).ok, false);
  chk('経路が台帳に無い→止まる', evaluate(L([rec()]), 'nope', C, dir).ok, false);
  const led = L([rec()]);
  const ledUnusable = L([rec({ usable_for_release: false })]);
  chk('印つきの記録でも文面の照合は通る（公開許可だけに効く）', scanClaims('Mac で動作検証済み。', 'R', ledUnusable, dir).length, 0);
  const c1 = scanClaims('Mac で動作検証済み。', 'R', led, dir), c2 = scanClaims('Windows で動作検証済み。', 'R', led, dir), c3 = scanClaims('Windows は未検証。署名検証済み', 'R', led, dir), c4 = scanClaims('署名検証済みのイベント', 'R', led, dir);
  chk('文面: macOS=3段記録あり→許す', c1.length, 0);
  chk('文面: 版付きの主張×その版の記録が公開許可に使えない→検出', scanClaims('macOS は実機で実動作まで確認（v0.13.0）。', 'R', L([rec({ artifact: 'v0.13.0 (abc1234)', usable_for_release: false })]), dir).length, 1);
  chk('文面: 版付きの主張×別の版の記録だけ→検出', scanClaims('macOS は実機で実動作まで確認（v0.13.0）。', 'R', L([rec({ artifact: 'v0.12.0 (abc1234)' })]), dir).length, 1);
  // 実際に公開文面に残っていた版付きの実機表現（回帰）
  for (const t of ['traffic was confirmed to stop and come back on GitHub\'s virtual runners (macOS and en-US Windows), and on macOS also on one real Mac with the v0.13.0 rules.',
    'on the real Mac, with the v0.13.0 rules, Zee\'s own restore alone returned pf state and network services to exactly what they were before.',
    '（macOS は実機1台でも v0.13.0 の規則で確認）。', '／macOS 実機では v0.13.0 の規則で、Zee 自身の復旧だけで pf の状態が実行前と同一に戻ることも確認。',
    '# 実機(MacBookPro17,1 / macOS 26.6.2)での Zee v0.13.0(7c70c9d) 実遮断と復旧の記録。'])
    chk(`文面: 版付きの実機表現×その版の使える記録なし→検出「${t.slice(0, 40)}」`, scanClaims(t, 'R', L([rec({ artifact: 'v0.13.0 (7c70c9d)', usable_for_release: false })]), dir).length, 1);
  chk('文面: 版付きの実機表現でも「版は実測していない」と書けば主張ではない', scanClaims('macOS 実機1台で確認（v0.13.0 の時期・動いたコードの版は実測していない）。', 'R', L([]), dir).length, 0);
  chk('文面: 版付きの主張×その版の使える記録→許す', scanClaims('macOS は実機で実動作まで確認（v0.13.0）。', 'R', L([rec({ artifact: 'v0.13.0 (abc1234)' })]), dir).length, 0); chk('文面: Windows=記録なし→検出', c2.length, 1);
  chk('文面: 否定文脈・環境語なしは検出しない', c3.length + c4.length, 0);
  chk('文面: 仮想環境の明記は3段表記なので検出しない', scanClaims('Real cuts were tested on GitHub Actions virtual runners (macOS).', 'R', L([]), dir).length, 0);
  chk('文面: 実機で動作を確認しています→台帳なしは検出', scanClaims('macOS では実機で動作を確認しています。', 'R', L([]), dir).length, 1);
  const forged = { product: 't', channels: {}, records: [{ tier: 3, env: 'macOS' }] };
  chk('文面: 証拠も版も無い偽記録では許さない', scanClaims('Mac で動作検証済み。', 'R', forged, dir).length, 1);
  for (const t of ['Mac は検証済み、Linux は未実施。', 'MAC で検証済み。', 'Mac で動作確認済。', 'macOS: 実機で実動作まで確認', 'Mac で動作<strong>検証</strong>済み。']) chk(`文面: 回避表記を検出「${t}」`, scanClaims(t, 'R', L([]), dir).length >= 1, true);
  chk('文面: 利用者への依頼文は主張ではない', scanClaims('必ず業者に「Windows 実機での動作確認」を依頼してください。', 'R', L([]), dir).length, 0);
  chk('担当名の表記ゆれ(Build Bot / build-bot)でも同一とみなす', evaluate(L([rec({ by: 'Build Bot', built_by: 'build-bot' })]), 'git-tag', C, dir).ok, false);
  for (const t of ['Mac は検証済みですが Linux は未実施。', 'Mac、Linux は検証済み。']) chk(`文面: 回避表記を検出「${t}」`, scanClaims(t, 'R', L([]), dir).length >= 1, true);
  chk('文面: Macだけ記録ありなら「Mac は検証済み、Linux は未実施」は通す', scanClaims('Mac は検証済み、Linux は未実施。', 'R', led, dir).length, 0);
  chk('文面: Macだけ記録ありで「Mac、Linux は検証済み」は検出', scanClaims('Mac、Linux は検証済み。', 'R', led, dir).length, 1);
  { const ln = path.join(dir, 'evidence', 'link.txt'); fs.writeFileSync(path.join(dir, 'outside.log'), 'real run log'); fs.symlinkSync('../outside.log', ln);
    chk('証拠がevidence/外へのシンボリックリンク→止まる', evaluate(L([rec({ evidence: 'evidence/link.txt', evidence_sha256: sha256(fs.readFileSync(ln)) })]), 'git-tag', C, dir).ok, false); }
  { const oe = console.error; let out = ''; console.error = (x) => { out += x + '\n'; }; const code = cmdCheck(['--channel', 'git-tag', '--artifact', '__missing_ref__']); console.error = oe;
    chk('check: 版が特定できなくても exit 1 と次の手を出す', code === 1 && out.includes('RELEASE_BLOCKED:'), true); }
  chk('文面: 同じ行に未実施の文が並んでも検証済みの文は検出', scanClaims('Mac で動作検証済み。Linux は未実施。', 'R', L([]), dir).length, 1);
  chk('文面: 台帳が空なら Mac の「検証済み」を検出', scanClaims('Mac で動作検証済み。', 'R', L([]), dir).length, 1);
  // vercel-ignore: 本番×記録なし→停止(≠7)・プレビュー→続行・台帳が壊れていても停止
  const run = (env, ledgerObj, raw) => { const p = path.join(dir, 'l.json'); fs.writeFileSync(p, raw ?? JSON.stringify(ledgerObj)); const save = { ...process.env }; process.env.VERCEL_ENV = env; const code = cmdVercelIgnore(['--ledger', p, '--channel', 'git-tag']); process.env = save; return code; };
  // vercel-ignore は作業ツリーのHEADの指紋を使う＝一時gitリポジトリで試す
  const gdir = path.join(tmp, 'g'); fs.mkdirSync(gdir); const gg = (...a) => execFileSync('git', ['-c', 'user.email=a@b', '-c', 'user.name=n', ...a], { cwd: gdir, stdio: 'ignore' });
  gg('init', '-q'); fs.writeFileSync(path.join(gdir, 'f.txt'), 'x'); gg('add', 'f.txt'); gg('commit', '-qm', 'i');
  const cwd0 = process.cwd(); process.chdir(gdir); const gid = contentId(gdir, 'HEAD');
  const origErr = console.error; console.error = () => {};
  const vProd = run('production', L([])), vPrev = run('preview', L([])), vBroken = run('production', null, '{broken'), vOk = run('production', L([rec({ content_id: gid })]));
  chk('指紋: docs/security/ だけ変えても変わらない', (() => { fs.mkdirSync(path.join(gdir, 'docs', 'security'), { recursive: true }); fs.writeFileSync(path.join(gdir, 'docs', 'security', 'l.json'), '{}'); gg('add', 'docs/security/l.json'); gg('commit', '-qm', 'l'); return contentId(gdir, 'HEAD'); })(), gid);
  chk('指紋: 他のファイルを変えたら変わる', (() => { fs.writeFileSync(path.join(gdir, 'f.txt'), 'y'); gg('add', 'f.txt'); gg('commit', '-qm', 'f'); return contentId(gdir, 'HEAD') !== gid; })(), true);
  process.chdir(cwd0);
  console.error = origErr;
  chk('vercel: 本番×記録なし→停止', vProd !== PROCEED, true); chk('vercel: プレビュー→続行', vPrev, PROCEED);
  chk('vercel: 台帳が壊れている→停止（異常でも通さない）', vBroken !== PROCEED, true); chk('vercel: 本番×合格記録→続行', vOk, PROCEED);
  console.log(bad ? `\n自己検査 ${bad} 件失敗` : '\n自己検査 すべて合格');
  return bad ? 1 : 0;
}

const [cmd, ...rest] = process.argv.slice(2);
if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  let code;
  try {
    code = cmd === '--selftest' ? selftest() : cmd === 'check' ? cmdCheck(rest) : cmd === 'id' ? (console.log(contentId(process.cwd(), resolveCommit(process.cwd(), rest[0] || 'HEAD'))), 0) : cmd === 'vercel-ignore' ? cmdVercelIgnore(rest) : cmd === 'claims' ? cmdClaims(rest)
      : (console.error('使い方: check | vercel-ignore | claims | --selftest（ファイル先頭を参照）'), 2);
  } catch (e) { console.error(`✖ 関門の実行に失敗（通さない）: ${e.message}`); code = cmd === 'vercel-ignore' ? 0 : 1; }
  process.exit(code);
}
