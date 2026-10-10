import { chromium } from "playwright";

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1600, height: 900 } });
const errs = [];
page.on("pageerror", (e) => errs.push(e.message));
await page.goto("http://127.0.0.1:8766/#token=UXgF4cb44InmOr6xyXPNebZ0pXHTAfbH91bgwPdFtUI", {
  waitUntil: "networkidle",
});
await page.waitForTimeout(2000);
await page.screenshot({ path: "C:/Temp/rt-v2-first.png" });
// click fat16 run — find by run containing fat16 evidence; just click first
await page.locator(".run-item").first().click();
await page.waitForTimeout(2500);
await page.screenshot({ path: "C:/Temp/rt-v2-detail.png" });
console.log("errors:", errs.length ? errs : "none");
await browser.close();
