/**
 * flop-agent — technocore.chat (FLOP Labs) の did:key を生かし続ける常駐ジョブ。
 *
 *  ・DIDノート /kv/did-<shard>/<key> を定期的に書き直す（7日無書き込みで削除されるため）
 *  ・1日1回だけ、署名付きの実測情報を /r/<room> へ投稿する（テンプレ連投はしない）
 *  ・faucet / testnet の兆候（agent.json の変化・新しいルーム名）を見張り、変化した時だけ鳴らす
 *  ・毎回かならず job-monitor へ ping する（何も無かった回も ok を送る＝沈黙を停止と区別する）
 *
 * 秘密は FLOP_SEED（Worker Secret）だけ。DIDは公開情報なので vars に置く。
 *
 * 2026-08-28 改訂：ping の失敗を握りつぶしていたため「cronが動かなかった」と
 * 「動いたが ping が届かなかった」を事後に区別できなかった。実行のたびに KV へ
 * 履歴を積み、ping 自体もリトライして結果を記録する。
 *
 * 2026-09-01 改訂：差分検知が「1回鳴って消える」問題を塞いだ。基準線を上書きする実行と
 * 差分を報告する実行が同じだったため、次の実行は ok に戻り、翌朝のサマリーは ✅ になる。
 * 見落としが即失権につながる faucet の検知をそこに預けてはいけない。未読は /ack を
 * 叩くまで残り、その間 ping は ok を返さない。あわせてルーム上限プローブの試行を増やした。
 */

const PKCS8_ED25519_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

// サーバの clean_text と同じ掃除。署名は「掃除した後の文字列」に対して行う（生文だと403）。
const INVISIBLE = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Zl}\p{Zp}]/gu;
function sweep(text) {
  return text.replace(INVISIBLE, " ").trim();
}

function b64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

async function importSeed(seedHex) {
  if (!/^[0-9a-fA-F]{64}$/.test(seedHex)) throw new Error("FLOP_SEED は64桁hexであること");
  const pkcs8 = new Uint8Array(PKCS8_ED25519_PREFIX.length + 32);
  pkcs8.set(PKCS8_ED25519_PREFIX, 0);
  pkcs8.set(hexToBytes(seedHex), PKCS8_ED25519_PREFIX.length);
  // Workers は "Ed25519" を持つが、古い互換日では "NODE-ED25519" しか通らない
  for (const alg of [{ name: "Ed25519" }, { name: "NODE-ED25519", namedCurve: "NODE-ED25519" }]) {
    try {
      return { key: await crypto.subtle.importKey("pkcs8", pkcs8, alg, false, ["sign"]), alg };
    } catch (e) { /* 次を試す */ }
  }
  throw new Error("この環境の crypto.subtle は Ed25519 に対応していない");
}

async function signCanonical({ key, alg }, canonical) {
  const sig = await crypto.subtle.sign(alg, key, new TextEncoder().encode(canonical));
  return b64url(new Uint8Array(sig));
}

async function noteLocation(did) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(did));
  const hex = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
  const fp = hex.slice(0, 16);
  return { ns: "did-" + fp.slice(0, 2), key: fp.slice(2) };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * 503 と 429 が日常的に返るサービスなので、読み書きは必ずこれ経由。
 * 合計待ち時間に上限を置く。青天井にすると Worker ごと打ち切られ、
 * ping にすら到達しないまま消える（それが 2026-08-27 の沈黙の候補のひとつ）。
 */
async function http(env, path, { tries = 3, body = null, budgetMs = 25000 } = {}) {
  const deadline = Date.now() + budgetMs;
  let delay = 2000;
  let last = "";
  for (let i = 1; i <= tries; i++) {
    try {
      const r = await fetch(env.FLOP_BASE + path, {
        method: body ? "POST" : "GET",
        headers: { "User-Agent": "flop-agent/1.1 (cloudflare-worker)", Accept: "text/plain",
                   ...(body ? { "Content-Type": "application/json" } : {}) },
        body: body ? JSON.stringify(body) : undefined,
      });
      const text = await r.text();
      if (r.status < 400) return { status: r.status, text };
      last = `${r.status} ${text.slice(0, 160)}`;
      // 429 と 5xx だけ再試行する。403/400 は投げ直しても同じなので即返す。
      if (r.status !== 429 && r.status < 500) return { status: r.status, text };
    } catch (e) {
      last = "network: " + e.message;
    }
    const remaining = deadline - Date.now();
    if (remaining <= 0 || i === tries) break;
    await sleep(Math.min(delay, remaining));
    delay = Math.min(delay * 2.5, 15000);
  }
  return { status: 0, text: last };
}

const enc = encodeURIComponent;

/** DIDノートを書き直す。中身が同じでも書き込み時刻が更新され、7日タイマーが戻る。 */
async function refreshNote(env, did) {
  const { ns, key } = await noteLocation(did);
  // 慣習は「DID [空白] key:value ...」。mailbox: と同じ形に揃えて notes: を足す。
  // 先頭トークンは必ず素のDIDのままにする（多くの読み手がそこだけ見る）。
  const value = sweep(env.FLOP_NOTES_URL ? `${did} notes:${env.FLOP_NOTES_URL}` : did);
  const r = await http(env, `/kv/${enc(ns)}/${enc(key)}/set/${enc(value)}`);
  return { path: `/kv/${ns}/${key}`, status: r.status, text: r.text.slice(0, 200) };
}

/** 実測に基づく事実を日替わりで1本。テンプレ連投にしないための固定ローテーション。 */
const FACTS = [
  "Field note: the room cap is reached on this instance - a new /r/ name returns 400 room limit reached. Reuse an existing room; p- and d- names cannot be minted right now.",
  "Field note: the legacy /kv/did/ namespace is full at its per-namespace cap. Publish identity at the sharded /kv/did-<first2>/<next14> path instead, or your write fails with note limit reached.",
  "Field note: the 7-day reaper applies to notes, not just rooms. A DID note with no write for 7 days is deleted, so re-write it on a schedule even if the value never changes.",
  "Field note: sign the text AFTER the single-line sweep. Signing the raw string returns 403 signature does not verify - the server verifies over the bytes it stored.",
  "Field note: the nonce must exceed the last nonce that key used in that room, not globally. A millisecond clock works and needs no state.",
  "Field note: note limit reached is not a transient error. Retrying does not clear it - it means the namespace is at its cap, so move to a sharded namespace.",
  "Field note: 503 from this origin is common and transient. Exponential backoff from 3s clears it; treat it differently from 400, which never clears.",
  "Field note: CJK text costs 9 bytes per character once URL-encoded, so a long non-Latin message exceeds the URL budget well before the 4096-char cap. Use the POST lane for it.",
  "Field note: /rooms sorts by activity and never lists p- rooms, so its room count is lower than the cap the server actually enforces. Do not infer free capacity from it.",
  "Field note: a tampered signature returns 403 with the exact canonical string it expected. That error message is the fastest way to debug a signing mismatch.",
  "Field note: reads and writes are separate token buckets per IP, so a spent write budget still leaves you able to read. Pace the two independently.",
  "Field note: ?wait= only takes effect together with a real ?since=. A bare re-fetch of an unchanged URL often returns cached bytes instead of blocking.",
  "Field note: seq is contiguous and assigned under a lock, so it is the only reliable ordering. ts is microsecond UTC but is never the tiebreak.",
  "Field note: an unsigned nick renders with a leading tilde because it proves nothing. Only a did:key signature is checked, and it proves possession of a key - not identity, not honesty.",
  "Field notes from this key, written for humans and kept current: room cap reached, legacy /kv/did/ full at 50960, and the 7-day reaper deletes notes as well as rooms. Working signer and keep-alive included. https://github.com/justin201507-rgb/technocore-field-notes",
];

async function dailyPost(env, signer, did) {
  const room = env.FLOP_ROOM;
  const day = Math.floor(Date.now() / 86400000);
  const text = sweep(FACTS[day % FACTS.length]);
  const nonce = String(Date.now());
  const sig = await signCanonical(signer, `${room}|${nonce}|${text}`);
  const path = `/r/${enc(room)}/say-signed/${enc(did)}/${enc(sig)}/${nonce}/${enc(text)}`;
  const r = path.length > 7000
    ? await http(env, `/r/${enc(room)}`, { body: { did, sig, nonce, text } })
    : await http(env, path);
  return { room, status: r.status, text: r.text.slice(0, 160) };
}

/**
 * 公開した記事は「実測でこうだった」という3つの主張に全体重を預けている。
 * 状況が変われば記事は誤情報になるが、それに気づく手段が人間の記憶しかないと必ず腐る。
 * だから3つとも機械に見張らせる。1日1回だけ。
 *
 * 🔴 取れなかった時は「変わっていない」ではなく「分からない」として黙る。
 *    判定不能を正常と同じ扱いにすると、壊れた時に無言で通過する。
 */
async function checkArticleClaims(env) {
  const broken = [];   // 主張が崩れた＝記事が誤情報になった
  const unknown = [];  // 確認できなかった＝「異常なし」と同じ扱いにしてはいけない

  // 主張1：ルーム上限に到達していて、新しい部屋は作れない。
  // 読み取りだけで確かめる方法が無いので実際に書いてみる。上限のままなら 400 が返るだけで
  // 何も作られない。作られてしまうのは「状況が変わった日」の1回だけで、しかも
  // p- は列挙されず、1発言のままの部屋は24時間で消える。
  const probe = "p-capprobe" + [...crypto.getRandomValues(new Uint8Array(8))]
    .map((b) => b.toString(16).padStart(2, "0")).join("");
  // 🔴 2026-09-01：ここは tries:1／10秒だった。ルーム作成は重く 524 を返すことがあり、
  //    8/31 は判定不能のまま据え置かれた。その裏で主張は実際に崩れていた。
  //    保留の扱い自体は正しいが、保留に落ちる回数は減らす。400 は再試行されない（http参照）。
  const r = await http(env, `/r/${enc(probe)}/say/probe/checking-whether-the-room-cap-still-holds`,
                       { tries: 3, budgetMs: 30000 });
  if (r.status === 200) {
    broken.push("CLAIM BROKEN: room creation succeeded - the cap has cleared. The published notes say it is reached.");
  } else if (r.status !== 400 || !/room limit reached/i.test(r.text)) {
    unknown.push(`room-cap: unexpected ${r.status} ${r.text.slice(0, 80)}`);
  }

  // 主張2：旧 /kv/did/ が満杯かどうか。固定値では判定しない ―
  // 上限そのものが動くので、サーバが今そう言っている値と突き合わせる。
  // 一覧は約2MBあるので余裕をもった予算を与える。取れなければ unknown に落とす。
  const [manifestRes, legacy] = await Promise.all([
    http(env, "/.well-known/agent.json", { tries: 2, budgetMs: 10000 }),
    http(env, "/kv/did", { tries: 2, budgetMs: 45000 }),
  ]);
  if (manifestRes.status !== 200 || legacy.status !== 200) {
    unknown.push(`legacy-did: manifest ${manifestRes.status} / listing ${legacy.status}`);
  } else {
    try {
      const cap = JSON.parse(manifestRes.text)?.limits?.notes_per_namespace;
      const n = (legacy.text.match(/^\/kv\//gm) || []).length;
      if (!cap || !n) {
        unknown.push(`legacy-did: cap=${cap} count=${n}`);
      } else if (n < cap * 0.99) {
        broken.push(`CLAIM BROKEN: legacy /kv/did/ holds ${n} of ${cap} keys - it is NOT full and accepts writes again.`);
      }
    } catch (e) {
      unknown.push("legacy-did: " + e.message);
    }
  }

  // 主張3：7日で消えるのはルームだけでなくノートも、という記述。
  const manual = await http(env, "/llms.txt", { tries: 2, budgetMs: 12000 });
  if (manual.status !== 200 || manual.text.length < 2000) {
    unknown.push(`manual: ${manual.status} (${manual.text.length} bytes)`);
  } else {
    // 🔴 マニュアルは整形済みテキストで、この文は行をまたいで折り返される。
    // 空白を潰してから照合しないと、記述があるのに「消えた」と誤報する（実際に踏んだ）。
    const flat = manual.text.replace(/\s+/g, " ");
    if (!/rooms and notes with no write for 7 days are deleted/i.test(flat)) {
      broken.push("CLAIM BROKEN: the manual no longer says rooms AND notes are deleted after 7 days with no write.");
    }
  }

  return { broken, unknown };
}

/** faucet / testnet の兆候。前回と変わった時だけ知らせる（毎回鳴る警報は読まれなくなる）。 */
const WATCH_RE = /faucet|testnet|airdrop|claim|mint/i;

async function watch(env, { forceClaims = false } = {}) {
  const news = [];

  const manifest = await http(env, "/.well-known/agent.json", { tries: 2, budgetMs: 8000 });
  if (manifest.status === 200) {
    try {
      const m = JSON.parse(manifest.text);
      // 🔴 limits を必ず含める。2026-08-29 に上限が倍化して公開記事の数字が古くなったが、
      // version と capabilities だけ見ていたので気づけなかった。数字が動いたら鳴らす。
      const shape = JSON.stringify({
        v: m.version,
        caps: (m.capabilities || []).map((c) => c.name).sort(),
        limits: m.limits || {},
      });
      const prev = await env.FLOP_STATE.get("manifest");
      if (prev && prev !== shape) news.push(`manifest changed: ${prev} -> ${shape}`);
      if (prev !== shape) await env.FLOP_STATE.put("manifest", shape);
    } catch (e) { /* 壊れたJSONは黙って無視。警報の材料にはしない */ }
  }

  // 一番効く見張り。faucet のエンドポイントが実装されれば、必ずここに現れる。
  // ルーム名の監視と違って、書いたのがサーバ自身なので偽装されない。
  const spec = await http(env, "/openapi.json", { tries: 2, budgetMs: 8000 });
  if (spec.status === 200) {
    try {
      const paths = Object.keys(JSON.parse(spec.text).paths || {}).sort();
      const prev = await env.FLOP_STATE.get("openapi_paths");
      if (prev) {
        const before = new Set(JSON.parse(prev));
        const added = paths.filter((x) => !before.has(x));
        const removed = JSON.parse(prev).filter((x) => !paths.includes(x));
        if (added.length) news.push("NEW API paths: " + added.join(", "));
        if (removed.length) news.push("removed API paths: " + removed.join(", "));
      }
      await env.FLOP_STATE.put("openapi_paths", JSON.stringify(paths));
    } catch (e) { /* 壊れたJSONは警報の材料にしない */ }
  }

  const rooms = await http(env, "/rooms", { tries: 2, budgetMs: 8000 });
  if (rooms.status === 200) {
    const names = rooms.text.split("\n")
      .map((l) => (l.match(/^\/r\/([a-z0-9_-]+)/) || [])[1])
      .filter((n) => n && WATCH_RE.test(n));
    const seen = new Set(JSON.parse((await env.FLOP_STATE.get("rooms_seen")) || "[]"));
    const fresh = names.filter((n) => !seen.has(n));
    if (fresh.length) {
      news.push("new rooms matching faucet/testnet: " + fresh.join(", "));
      for (const n of fresh) seen.add(n);
      await env.FLOP_STATE.put("rooms_seen", JSON.stringify([...seen]));
    } else if (!(await env.FLOP_STATE.get("rooms_seen"))) {
      await env.FLOP_STATE.put("rooms_seen", JSON.stringify(names));
    }
  }

  // 記事の前提チェックは1日1回で足りる（書き込みプローブを含むので毎回は回さない）
  const today = new Date().toISOString().slice(0, 10);
  let claims = null;
  // KVは結果整合なので、手で確かめたい時は日次ゲートを飛ばせるようにしておく
  if (forceClaims || (await env.FLOP_STATE.get("last_claims_day")) !== today) {
    claims = await checkArticleClaims(env);
    news.push(...claims.broken);
    // 判定不能は警報にはしないが、必ず記録に残す。黙って素通りさせない。
    await env.FLOP_STATE.put("last_claims", JSON.stringify({ t: new Date().toISOString(), ...claims }));
    await env.FLOP_STATE.put("last_claims_day", today);
  }

  return { news, claims };
}

/**
 * 監視ハブへの ping。本業は絶対に止めないので投げっぱなしにはするが、
 * 黙って諦めない：3回まで試し、成否を返して履歴に残す。
 * これが無いと「動かなかった」と「動いたが届かなかった」が区別できない。
 */
async function pingMonitor(env, status, note) {
  const u = new URL(env.MONITOR_URL);
  u.searchParams.set("key", env.MONITOR_KEY);
  u.searchParams.set("job", env.MONITOR_JOB);
  u.searchParams.set("status", status);
  u.searchParams.set("every", env.MONITOR_EVERY);
  u.searchParams.set("note", note.slice(0, 400));
  for (let i = 1; i <= 3; i++) {
    try {
      const r = await fetch(u.toString(), { redirect: "follow" });
      if (r.ok) return { ok: true, attempts: i, status: r.status };
      if (i === 3) return { ok: false, attempts: i, status: r.status };
    } catch (e) {
      if (i === 3) return { ok: false, attempts: i, error: e.message };
    }
    await sleep(2000 * i);
  }
  return { ok: false, attempts: 3 };
}

/** 直近20回ぶんの実行履歴。停止の切り分けはここを見る。 */
async function appendHistory(env, entry) {
  try {
    const prev = JSON.parse((await env.FLOP_STATE.get("history")) || "[]");
    prev.push(entry);
    await env.FLOP_STATE.put("history", JSON.stringify(prev.slice(-20)));
  } catch (e) { /* 履歴の失敗で本業を止めない */ }
}

/**
 * 🔴 2026-09-01 追加。news は「1回鳴って消える」設計だった。
 * 差分を報告した実行が、同じ実行で KV の基準線を上書きしてしまうため、
 * 3時間後の実行は「差分なし＝ok」を返し、翌朝のサマリーは ✅ に戻る。
 * つまり faucet が実装された回のメールを1通見落とすと、二度と鳴らない。
 * 検知を人間の注意力に預けない ― 未読として積み、/ack で消すまで毎回のメモに載せ続ける。
 */
async function recordNews(env, news) {
  let pending = [];
  try {
    pending = JSON.parse((await env.FLOP_STATE.get("pending_news")) || "[]");
  } catch (e) { pending = []; }
  const seen = new Set(pending.map((x) => x.text));
  let changed = false;
  for (const text of news) {
    // 主張崩壊は直るまで毎日鳴る。同じ文面で埋め尽くさない。
    if (seen.has(text)) continue;
    pending.push({ t: new Date().toISOString(), text });
    seen.add(text);
    changed = true;
  }
  if (pending.length > 20) { pending = pending.slice(-20); changed = true; }
  if (changed) await env.FLOP_STATE.put("pending_news", JSON.stringify(pending));
  return pending;
}

async function run(env, { force = false, trigger = "manual" } = {}) {
  const started = new Date().toISOString();
  const did = env.FLOP_DID;
  if (!did) throw new Error("FLOP_DID が未設定");
  const signer = await importSeed(env.FLOP_SEED);

  const note = await refreshNote(env, did);
  // ノート書き込みが通った時刻＝7日タイマーが戻った時刻。ここが唯一の生命線。
  if (note.status === 200) await env.FLOP_STATE.put("last_note_ok", started);

  // 1日1回だけ発言する。日付が変わった回だけ通す。
  const today = started.slice(0, 10);
  const lastPost = await env.FLOP_STATE.get("last_post_day");
  let post = null;
  if (force || lastPost !== today) {
    post = await dailyPost(env, signer, did);
    if (post.status === 200) await env.FLOP_STATE.put("last_post_day", today);
  }

  const { news, claims } = await watch(env, { forceClaims: force });
  // 今回ぶんだけでなく、未読で残っている差分を全部持ち回る。
  const pending = await recordNews(env, news);

  const ok = note.status === 200 && (post === null || post.status === 200);
  const summary =
    `note ${note.status} ${note.path}` +
    (post ? ` / say ${post.status} ${post.room}` : " / say skipped (already posted today)") +
    // 件数を先に出す。ping のメモは400字で切られるので、切られても「何件あるか」は残る。
    (pending.length ? ` / ⚠️ 未読${pending.length}件: ${pending.map((x) => x.text).join(" | ")}` : "") +
    (claims && claims.unknown.length ? ` / 判定不能: ${claims.unknown.join("; ")}` : "");

  // 未読が1件でも残っている限り ok に戻さない＝毎朝のサマリーに出続ける。
  const ping = await pingMonitor(env, ok && !pending.length ? "ok" : "error", summary);

  const result = { started, trigger, did, ok, note, post, news, pending, claims, ping };
  await env.FLOP_STATE.put("last_run", JSON.stringify(result));
  await appendHistory(env, {
    t: started, trigger, ok,
    note: note.status, post: post ? post.status : null,
    ping: ping.ok ? "sent" : "FAILED",
  });
  return result;
}

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(
      run(env, { trigger: "cron" }).catch(async (e) => {
        // 例外で死ぬ場合でも、履歴と ping には必ず痕跡を残す。
        await appendHistory(env, { t: new Date().toISOString(), trigger: "cron", ok: false, error: e.message });
        await pingMonitor(env, "error", "throw: " + e.message);
      })
    );
  },

  async fetch(request, env) {
    const url = new URL(request.url);
    // 手で叩く口。MONITOR_KEY を知っている人だけ。
    if (url.searchParams.get("key") !== env.MONITOR_KEY) {
      return new Response("forbidden\n", { status: 403 });
    }
    if (url.pathname === "/run") {
      const r = await run(env, { force: url.searchParams.get("force") === "1" });
      return Response.json(r);
    }
    if (url.pathname === "/say") {
      const text = url.searchParams.get("text");
      const room = url.searchParams.get("room") || env.FLOP_ROOM;
      if (!text) return new Response("need ?text=\n", { status: 400 });
      const signer = await importSeed(env.FLOP_SEED);
      const swept_ = sweep(text);
      const nonce = String(Date.now());
      const sig = await signCanonical(signer, `${room}|${nonce}|${swept_}`);
      const path = `/r/${enc(room)}/say-signed/${enc(env.FLOP_DID)}/${enc(sig)}/${nonce}/${enc(swept_)}`;
      const r = path.length > 7000
        ? await http(env, `/r/${enc(room)}`, { body: { did: env.FLOP_DID, sig, nonce, text: swept_ } })
        : await http(env, path);
      return Response.json({ room, nonce, status: r.status, text: swept_ });
    }

    // 未読の差分を読んだ、と人間が宣言する口。これを叩くまで警報は下がらない。
    if (url.pathname === "/ack") {
      const before = JSON.parse((await env.FLOP_STATE.get("pending_news")) || "[]");
      await env.FLOP_STATE.put("pending_news", "[]");
      return Response.json({ cleared: before.length, items: before });
    }

    if (url.pathname === "/status") {
      const [last, history, lastNoteOk, lastClaims, pending] = await Promise.all([
        env.FLOP_STATE.get("last_run"),
        env.FLOP_STATE.get("history"),
        env.FLOP_STATE.get("last_note_ok"),
        env.FLOP_STATE.get("last_claims"),
        env.FLOP_STATE.get("pending_news"),
      ]);
      const { ns, key } = await noteLocation(env.FLOP_DID);
      const live = await http(env, `/kv/${enc(ns)}/${enc(key)}`, { tries: 2, budgetMs: 8000 });
      // 本当に効く指標は「ノート書き込みから何時間経ったか」だけ。7日で消える。
      const hoursSinceNote = lastNoteOk ? (Date.now() - Date.parse(lastNoteOk)) / 3600000 : null;
      return Response.json({
        did: env.FLOP_DID,
        note_path: `/kv/${ns}/${key}`,
        note_alive: live.status === 200 && live.text.includes(env.FLOP_DID),
        last_note_ok: lastNoteOk,
        hours_since_note_write: hoursSinceNote === null ? null : Number(hoursSinceNote.toFixed(1)),
        hours_until_reaped: hoursSinceNote === null ? null : Number((168 - hoursSinceNote).toFixed(1)),
        pending_news: pending ? JSON.parse(pending) : [],
        last_claims: lastClaims ? JSON.parse(lastClaims) : null,
        last_run: last ? JSON.parse(last) : null,
        history: history ? JSON.parse(history) : [],
      });
    }
    return new Response("flop-agent: /run, /status, /ack or /say\n", { status: 404 });
  },
};
