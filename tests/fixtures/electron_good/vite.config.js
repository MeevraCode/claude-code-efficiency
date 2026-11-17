// Test fixture: the build writes the enforced policy into index.html as a meta tag.
// The dev server only reports, so its policy must not count as enforced.
const PRODUCTION_CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'none'"
].join('; ');

const DEV_CSP_REPORT_ONLY = [
  "default-src 'none'",
  "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
  "connect-src 'self' ws://127.0.0.1:5173"
].join('; ');

function cspPlugin() {
  return {
    name: 'production-csp',
    apply: 'build',
    transformIndexHtml: () => [
      { tag: 'meta', attrs: { 'http-equiv': 'Content-Security-Policy', content: PRODUCTION_CSP }, injectTo: 'head-prepend' }
    ]
  };
}

export default {
  plugins: [cspPlugin()],
  server: {
    headers: { 'Content-Security-Policy-Report-Only': DEV_CSP_REPORT_ONLY }
  }
};
