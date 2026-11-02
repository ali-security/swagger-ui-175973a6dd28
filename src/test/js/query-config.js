/**
 * Regression tests for CVE-2018-25031 (GHSA-cr3q-pqgq-m8c2).
 *
 * Swagger UI before 4.1.3 read its configuration from the page's query string
 * (`?url=`, `?configUrl=`, `?config=`, ...). A crafted link could therefore make
 * a trusted Swagger UI page fetch and display a remote, attacker-controlled
 * OpenAPI definition or configuration (spoofing / request to an arbitrary host).
 *
 * The fix (swagger-ui commit 01a3e55) adds the `queryConfigEnabled` option,
 * default `false`, and only honours query-string configuration when it is
 * explicitly enabled.
 *
 * These tests run against the PACKAGED WebJar bundles - the exact files shipped
 * in the jar. The Maven build stages this file into the upstream swagger-ui
 * test/unit/webjar/ directory and substitutes the WebJar resource directory
 * below; it then runs with upstream's jest unit configuration.
 */
const fs = require("fs")
const path = require("path")

const WEBJAR_DIR = "@WEBJAR_DIR@"

const BUNDLES = [
  "swagger-ui-bundle.js",
  "swagger-ui-es-bundle.js",
  "swagger-ui.js",
  "swagger-ui-es-bundle-core.js",
]

const TRUSTED_SPEC = "https://trusted.invalid/openapi.json"
const ATTACKER_SPEC = "https://attacker.invalid/evil-openapi.yaml"
const ATTACKER_CONFIG = "https://attacker.invalid/evil-config.json"
const ATTACKER_REDIRECT = "https://attacker.invalid/steal-token.html"

function loadBundle(file) {
  const source = fs.readFileSync(path.join(WEBJAR_DIR, file), "utf8")
  const mod = { exports: {} }
  // eslint-disable-next-line no-new-func
  new Function("module", "exports", "require", source)(mod, mod.exports, require)
  return typeof mod.exports === "function" ? mod.exports : mod.exports.default
}

function setQueryString(search) {
  window.history.replaceState(null, "", "/" + search)
}

// Let pending (failed) fetches settle so their handlers have run.
function settle() {
  return new Promise((resolve) => setTimeout(resolve, 50))
}

// Boots Swagger UI without rendering. Every outbound request goes through the
// requestInterceptor, which records the target URL and aborts the request so
// that no network traffic leaves the test.
function boot(SwaggerUI, opts) {
  const requested = []
  const ui = SwaggerUI(Object.assign({
    dom_id: null,
    requestInterceptor: (req) => {
      requested.push(req.url)
      throw new Error("outbound request blocked by test: " + req.url)
    },
  }, opts))
  return { ui, requested }
}

describe("webjar: CVE-2018-25031 query-string configuration", () => {
  let consoleError

  beforeEach(() => {
    consoleError = jest.spyOn(console, "error").mockImplementation(() => {})
  })

  afterEach(() => {
    setQueryString("")
    consoleError.mockRestore()
  })

  describe.each(BUNDLES)("%s", (file) => {
    let SwaggerUI

    beforeAll(() => {
      SwaggerUI = loadBundle(file)
    })

    it("should export the SwaggerUI constructor", () => {
      expect(SwaggerUI).toBeInstanceOf(Function)
    })

    it("should default queryConfigEnabled to false", async () => {
      const { ui } = boot(SwaggerUI, {})
      await settle()

      expect(ui.getConfigs().queryConfigEnabled).toBe(false)
    })

    it("should ignore ?url= and load the configured definition", async () => {
      setQueryString("?url=" + encodeURIComponent(ATTACKER_SPEC))

      const { ui, requested } = boot(SwaggerUI, { url: TRUSTED_SPEC })
      await settle()

      expect(requested).not.toContain(ATTACKER_SPEC)
      expect(requested).toEqual([TRUSTED_SPEC])
      expect(ui.getConfigs().url).toEqual(TRUSTED_SPEC)
      expect(ui.specSelectors.url()).toEqual(TRUSTED_SPEC)
    })

    it("should ignore ?url= when no definition is configured", async () => {
      setQueryString("?url=" + encodeURIComponent(ATTACKER_SPEC))

      const { ui, requested } = boot(SwaggerUI, {})
      await settle()

      expect(requested).toEqual([])
      expect(ui.getConfigs().url).toEqual("")
    })

    it("should ignore ?configUrl=", async () => {
      setQueryString("?configUrl=" + encodeURIComponent(ATTACKER_CONFIG))

      const { ui, requested } = boot(SwaggerUI, { url: TRUSTED_SPEC })
      await settle()

      expect(requested).not.toContain(ATTACKER_CONFIG)
      expect(requested).toEqual([TRUSTED_SPEC])
      expect(ui.getConfigs().configUrl).toBeUndefined()
    })

    it("should ignore ?config=", async () => {
      setQueryString("?config=" + encodeURIComponent(ATTACKER_CONFIG))

      const { requested } = boot(SwaggerUI, { url: TRUSTED_SPEC })
      await settle()

      expect(requested).not.toContain(ATTACKER_CONFIG)
      expect(requested).toEqual([TRUSTED_SPEC])
    })

    it("should not let the query string override other configuration", async () => {
      setQueryString(
        "?oauth2RedirectUrl=" + encodeURIComponent(ATTACKER_REDIRECT)
        + "&url=" + encodeURIComponent(ATTACKER_SPEC)
      )

      const { ui } = boot(SwaggerUI, { url: TRUSTED_SPEC })
      await settle()

      const defaultRedirect = window.location.protocol + "//" + window.location.host + "/oauth2-redirect.html"
      expect(ui.getConfigs().oauth2RedirectUrl).not.toEqual(ATTACKER_REDIRECT)
      expect(ui.getConfigs().oauth2RedirectUrl).toEqual(defaultRedirect)
      expect(ui.getConfigs().url).toEqual(TRUSTED_SPEC)
    })

    it("should still honour the query string when queryConfigEnabled is true", async () => {
      setQueryString("?url=" + encodeURIComponent(ATTACKER_SPEC))

      const { ui, requested } = boot(SwaggerUI, {
        url: TRUSTED_SPEC,
        queryConfigEnabled: true,
      })
      await settle()

      expect(requested).toEqual([ATTACKER_SPEC])
      expect(ui.getConfigs().url).toEqual(ATTACKER_SPEC)
    })
  })
})
