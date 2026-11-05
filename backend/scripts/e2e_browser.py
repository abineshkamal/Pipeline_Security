"""Browser E2E check using the locally installed Microsoft Edge (Playwright channel=msedge).

    python scripts/e2e_browser.py http://127.0.0.1:8000 E:/dev-cache/shots
"""
import sys
import time
import uuid
import zipfile
from pathlib import Path

from playwright.sync_api import sync_playwright

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
SHOTS = Path(sys.argv[2] if len(sys.argv) > 2 else "shots")
SHOTS.mkdir(parents=True, exist_ok=True)
SAMPLES = Path(__file__).resolve().parents[2] / "samples"
errors: list[str] = []
checks: list[str] = []


def ok(msg):
    checks.append(msg)
    print("PASS", msg)


def make_zip() -> Path:
    z = SHOTS / "vulnerable-repo.zip"
    with zipfile.ZipFile(z, "w") as zf:
        for p in (SAMPLES / "vulnerable-repo").rglob("*"):
            if p.is_file():
                zf.write(p, "vulnerable-repo-main/" + p.relative_to(SAMPLES / "vulnerable-repo").as_posix())
    return z


with sync_playwright() as pw:
    browser = pw.chromium.launch(channel="msedge", headless=True)
    ctx = browser.new_context(viewport={"width": 1400, "height": 900})
    page = ctx.new_page()
    page.on("console", lambda m: errors.append(f"console.{m.type}: {m.text}") if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))

    email = f"e2e-{uuid.uuid4().hex[:6]}@pipelinetrust.example.com"
    page.goto(BASE + "/")
    page.wait_for_url("**/login")
    page.screenshot(path=str(SHOTS / "01-login.png"))
    page.click("text=Create an organization")
    page.fill("#org", "E2E Security Team")
    page.fill("#name", "E2E Analyst")
    page.fill("#email", email)
    page.fill("#pw", "Str0ng!Passw0rd")
    page.click("button:has-text('Create account')")
    page.wait_for_url("**/dashboard")
    page.wait_for_selector("text=No projects yet")
    ok("register -> empty dashboard")

    page.click("a:has-text('Create a project')")
    page.wait_for_url("**/projects")
    page.fill("#pn", "Vulnerable Sample")
    page.select_option("#ps", "upload")
    page.click("button:has-text('Create project')")
    page.click("a.fw-semibold:has-text('Vulnerable Sample')")
    page.wait_for_url("**/project?id=*")
    page.wait_for_selector("#zip")
    # keep the scan quick: only fast tools
    for t in ["trivy", "syft"]:
        cb = page.locator(f"#t-{t}")
        if cb.is_checked():
            cb.uncheck()
    page.set_input_files("#zip", str(make_zip()))
    page.screenshot(path=str(SHOTS / "02-project.png"))
    page.click("button:has-text('Start scan')")
    page.wait_for_selector("a:has-text('View results')", timeout=180_000)
    ok("ZIP upload scan completed via UI")
    page.click("a:has-text('View results')")
    page.wait_for_url("**/scan?id=*")
    page.wait_for_selector("text=OWASP CI/CD category scores")
    time.sleep(1)
    page.screenshot(path=str(SHOTS / "03-scan-overview.png"), full_page=True)
    ok("scan overview rendered")

    page.click("button.nav-link:has-text('Controls')")
    page.wait_for_selector("text=PT-PPE-001")
    page.screenshot(path=str(SHOTS / "04-controls.png"))
    ok("control matrix rendered")

    page.click("button.nav-link:has-text('Findings')")
    page.wait_for_selector("tr.finding-row")
    n = page.locator("tr.finding-row").count()
    page.locator("tr.finding-row").first.click()
    page.wait_for_selector("text=Save triage")
    page.select_option("#tri", "confirmed")
    page.fill("#note", "Verified during E2E")
    page.click("button:has-text('Save triage')")
    page.wait_for_selector("text=Saved")
    page.screenshot(path=str(SHOTS / "05-findings.png"))
    ok(f"findings list ({n} rows) + triage saved")

    page.click("button.nav-link:has-text('Attack paths')")
    page.wait_for_selector(".react-flow__node", timeout=20_000)
    time.sleep(1.5)
    nodes = page.locator(".react-flow__node").count()
    page.screenshot(path=str(SHOTS / "06-attack-paths.png"))
    ok(f"attack graph rendered ({nodes} nodes)")

    page.click("button.nav-link:has-text('AI analysis')")
    page.wait_for_selector("text=Executive summary")
    page.screenshot(path=str(SHOTS / "07-ai.png"))
    ok("AI analysis panel rendered")

    page.click("button.nav-link:has-text('Inventory')")
    page.wait_for_selector("text=Actions and images")
    page.click("button.nav-link:has-text('Tools')")
    page.wait_for_selector("td:has-text('gitleaks')")
    ok("inventory + tools tabs")

    with page.expect_download() as dl:
        page.click("button:has-text('HTML report')")
    d = dl.value
    target = SHOTS / "report.html"
    d.save_as(str(target))
    assert "CI/CD Security Assessment Report" in target.read_text("utf-8")
    with page.expect_download() as dl2:
        page.click("button:has-text('SARIF')")
    dl2.value.save_as(str(SHOTS / "report.sarif"))
    ok("HTML + SARIF downloads")

    rp = ctx.new_page()
    rp.goto(target.as_uri())
    rp.screenshot(path=str(SHOTS / "08-report.png"))
    rp.close()

    # GitHub connector via UI (public repo, no token)
    page.goto(BASE + "/projects")
    page.fill("#pn", "GitHub sample")
    page.select_option("#ps", "github")
    page.fill("#pr", "actions/hello-world-javascript-action")
    page.click("button:has-text('Create project')")
    page.click("a.fw-semibold:has-text('GitHub sample')")
    page.wait_for_selector("button:has-text('Start scan')")
    for t in ["trivy", "syft"]:
        cb = page.locator(f"#t-{t}")
        if cb.is_checked():
            cb.uncheck()
    page.click("button:has-text('Start scan')")
    page.wait_for_selector("a:has-text('View results')", timeout=240_000)
    ok("GitHub public-repo scan completed via UI")

    page.goto(BASE + "/dashboard")
    page.wait_for_selector("text=Average score by OWASP CI/CD category")
    time.sleep(1)
    page.screenshot(path=str(SHOTS / "09-dashboard.png"), full_page=True)
    ok("dashboard with data")

    page.goto(BASE + "/settings")
    page.wait_for_selector("text=Audit log")
    page.screenshot(path=str(SHOTS / "10-settings.png"))
    page.goto(BASE + "/rules")
    page.wait_for_selector("text=PT-PPE-003")
    ok("settings + rules pages")

    # phone width: no horizontal page scroll
    m = browser.new_context(viewport={"width": 390, "height": 844}, storage_state=ctx.storage_state())
    mp = m.new_page()
    mp.on("pageerror", lambda e: errors.append(f"mobile pageerror: {e}"))
    mp.goto(page.url.replace("/rules", "/dashboard"))
    mp.wait_for_selector("text=Average score by OWASP CI/CD category")
    sw = mp.evaluate("document.documentElement.scrollWidth")
    mp.screenshot(path=str(SHOTS / "11-mobile-dashboard.png"), full_page=True)
    assert sw <= 392, f"horizontal overflow at phone width: {sw}px"
    ok(f"phone width layout (scrollWidth {sw})")
    browser.close()

print("\nCHECKS", len(checks))
print("BROWSER ERRORS", len(errors))
for e in errors:
    print("  ", e)
sys.exit(1 if errors else 0)
