import { chromium } from "playwright";

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1600, height: 900 } });
const errs = [];
page.on("pageerror", (e) => errs.push(e.message));
await page.goto("http://127.0.0.1:8766/#token=UXgF4cb44InmOr6xyXPNebZ0pXHTAfbH91bgwPdFtUI", {
  waitUntil: "networkidle",
});
await page.waitForTimeout(2000);
await page.screenshot({ path: "C:/Temp/rt-runs.png" });
// click first run item
const item = page.locator(".run-item").first();
console.log("run items:", await page.locator(".run-item").count());
await item.click();
await page.waitForTimeout(3000);
await page.screenshot({ path: "C:/Temp/rt-detail.png", fullPage: false });
// also screenshot scrolled
console.log("errors:", errs);
await browser.close();
