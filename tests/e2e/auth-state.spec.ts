import { test, expect, type Page } from "@playwright/test";

const responseDetail = "応答本文のテスト専用詳細は画面に表示しない";

async function expectUnavailable(page: Page, code: string) {
  await expect(page.getByRole("button", { name: "接続を再確認", exact: true })).toBeVisible();
  const notice = page.locator('.auth-panel [role="alert"]');
  await expect(notice).toContainText(code);
  // API本文やブラウザの例外をそのまま表示せず、固定の確認番号だけを診断に使う。
  await expect(notice).not.toContainText(responseDetail);
  await expect(notice).not.toContainText(/Failed to fetch|NetworkError|TypeError|SyntaxError/);
  await expect(page.getByRole("button", { name: "パスキーでログイン", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "パスキーを登録", exact: true })).toHaveCount(0);
}

// 認証状態の画面分岐を架空応答で検査する。受付資格の実認可は実APIの通し確認で維持する。
test("受付端末だけの403でも管理者のパスキーログインを表示する", async ({ page }) => {
  await page.route("**/api/admin/me", (route) => route.fulfill({ status: 403, json: { code: "FORBIDDEN" } }));
  await page.route("**/api/setup/status", (route) => route.fulfill({ json: { completed: true } }));
  await page.goto("/");
  await expect(page.getByRole("button", { name: "パスキーでログイン", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "接続を再確認", exact: true })).toHaveCount(0);
  await expect(page.locator('.auth-panel [role="alert"]')).toHaveCount(0);
});

for (const failure of [
  { name: "異なるOrigin", status: 403, code: "ORIGIN_DENIED" },
  { name: "未知の権限エラー", status: 403, code: "UNKNOWN_DENIAL" },
  { name: "APIの障害", status: 503, code: "UNAVAILABLE" },
]) {
  test(`${failure.name}を未ログインと誤認せず接続の再確認を案内する`, async ({ page }) => {
    let setupRequests = 0;
    await page.route("**/api/admin/me", (route) => route.fulfill({ status: failure.status, json: { code: failure.code, message: responseDetail } }));
    await page.route("**/api/setup/status", (route) => {
      setupRequests++;
      return route.fulfill({ json: { completed: true } });
    });
    await page.goto("/");
    await expectUnavailable(page, `ADMIN_HTTP_${failure.status}`);
    expect(setupRequests).toBe(0);
  });
}

test("JSONでない403をログイン状態の応答として扱わない", async ({ page }) => {
  await page.route("**/api/admin/me", (route) => route.fulfill({ status: 403, contentType: "text/html", body: `<p>${responseDetail}</p>` }));
  await page.goto("/");
  await expectUnavailable(page, "ADMIN_HTTP_403");
});

test("接続の再確認で401に戻ればパスキーログインへ進める", async ({ page }) => {
  let available = false;
  await page.route("**/api/admin/me", (route) => available
    ? route.fulfill({ status: 401, json: { code: "UNAUTHENTICATED" } })
    : route.fulfill({ status: 503, json: { code: "UNAVAILABLE" } }));
  await page.route("**/api/setup/status", (route) => route.fulfill({ json: { completed: true } }));
  await page.goto("/");
  const retry = page.getByRole("button", { name: "接続を再確認", exact: true });
  await expectUnavailable(page, "ADMIN_HTTP_503");
  available = true;
  await retry.click();
  await expect(page.getByRole("button", { name: "パスキーでログイン", exact: true })).toBeVisible();
  await expect(retry).toHaveCount(0);
  await expect(page.locator('.auth-panel [role="alert"]')).toHaveCount(0);
});

for (const stage of ["ADMIN", "SETUP"] as const) {
  test(`${stage}の通信失敗を固定の確認番号で区別する`, async ({ page }) => {
    await page.route("**/api/admin/me", (route) => stage === "ADMIN"
      ? route.abort("failed")
      : route.fulfill({ status: 401, json: { code: "UNAUTHENTICATED" } }));
    await page.route("**/api/setup/status", (route) => route.abort("failed"));
    await page.goto("/");
    await expectUnavailable(page, `${stage}_NETWORK`);
  });

  test(`${stage}の200応答がJSONでない場合も正常状態へ進まない`, async ({ page }) => {
    const invalid = { status: 200, contentType: "application/json", body: responseDetail };
    await page.route("**/api/admin/me", (route) => stage === "ADMIN"
      ? route.fulfill(invalid)
      : route.fulfill({ status: 401, json: { code: "UNAUTHENTICATED" } }));
    await page.route("**/api/setup/status", (route) => route.fulfill(invalid));
    await page.goto("/");
    await expectUnavailable(page, `${stage}_INVALID_RESPONSE`);
  });
}

test("管理者の200応答が必要な項目を満たさなければ結果を確認できないと案内する", async ({ page }) => {
  await page.route("**/api/admin/me", (route) => route.fulfill({ json: { user: {}, message: responseDetail } }));
  await page.goto("/");
  await expectUnavailable(page, "ADMIN_INVALID_RESPONSE");
});

test("初期設定状態の503は管理者認証の失敗と区別する", async ({ page }) => {
  await page.route("**/api/admin/me", (route) => route.fulfill({ status: 401, json: { code: "UNAUTHENTICATED" } }));
  await page.route("**/api/setup/status", (route) => route.fulfill({ status: 503, json: { code: "UNAVAILABLE", message: responseDetail } }));
  await page.goto("/");
  await expectUnavailable(page, "SETUP_HTTP_503");
});

for (const invalid of [
  { name: "完了状態がない", json: { message: responseDetail } },
  { name: "完了状態が文字列", json: { completed: "true", message: responseDetail } },
]) {
  test(`初期設定の200応答で${invalid.name}場合は登録・ログインを表示しない`, async ({ page }) => {
    await page.route("**/api/admin/me", (route) => route.fulfill({ status: 401, json: { code: "UNAUTHENTICATED" } }));
    await page.route("**/api/setup/status", (route) => route.fulfill({ json: invalid.json }));
    await page.goto("/");
    await expectUnavailable(page, "SETUP_INVALID_RESPONSE");
  });
}

test("接続の再確認でも失敗した工程の確認番号を更新する", async ({ page }) => {
  let retried = false;
  await page.route("**/api/admin/me", (route) => retried
    ? route.fulfill({ status: 401, json: { code: "UNAUTHENTICATED" } })
    : route.fulfill({ status: 503, json: { code: "UNAVAILABLE", message: responseDetail } }));
  await page.route("**/api/setup/status", (route) => route.fulfill({ status: 503, json: { code: "UNAVAILABLE", message: responseDetail } }));
  await page.goto("/");
  await expectUnavailable(page, "ADMIN_HTTP_503");
  retried = true;
  await page.getByRole("button", { name: "接続を再確認", exact: true }).click();
  await expectUnavailable(page, "SETUP_HTTP_503");
  await expect(page.locator('.auth-panel [role="alert"]')).not.toContainText("ADMIN_HTTP_503");
});

for (const phase of ["initial", "retry"] as const) {
  test(`${phase === "initial" ? "初回読込" : "接続の再確認"}の未知の内部例外は詳細を表示しない`, async ({ page }) => {
    await page.addInitScript(({ phase, detail }) => {
      const originalFetch = window.fetch.bind(window);
      let adminRequests = 0;
      window.fetch = async (...args) => {
        const response = await originalFetch(...args);
        const input = args[0];
        const url = input instanceof Request ? input.url : String(input);
        if (new URL(url, location.href).pathname === "/api/admin/me") {
          adminRequests++;
          if (phase === "initial" || adminRequests > 1) {
            // 通信成功後に生じる想定外の例外を作り、通信失敗とは別の経路で秘匿を検査する。
            Object.defineProperty(response, "ok", { get() { throw new Error(detail); } });
          }
        }
        return response;
      };
    }, { phase, detail: responseDetail });
    await page.route("**/api/admin/me", (route) => route.fulfill({ status: 503, json: { code: "UNAVAILABLE" } }));
    await page.goto("/");
    if (phase === "retry") {
      await expectUnavailable(page, "ADMIN_HTTP_503");
      await page.getByRole("button", { name: "接続を再確認", exact: true }).click();
    }
    await expectUnavailable(page, "STATE_UNKNOWN");
  });
}
