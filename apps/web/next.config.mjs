const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000';
const isDev = process.env.NODE_ENV !== 'production';

// Hito 4 (PoC-02 / RS-02): cabeceras de defensa en profundidad contra XSS y
// clickjacking (antes ausentes: alertas ZAP 10038, 10020, 10021, 10037).
// 'unsafe-inline' en script-src es necesario para los scripts de hidratación
// de Next.js sin nonce; la defensa principal contra XSS es que React escape la
// salida (se eliminó dangerouslySetInnerHTML). 'unsafe-eval' solo en desarrollo.
const csp = [
  "default-src 'self'",
  `script-src 'self' 'unsafe-inline'${isDev ? " 'unsafe-eval'" : ''}`,
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self' data:",
  `connect-src 'self' ${API_URL}`,
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join('; ');

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  transpilePackages: ['@secure-crm/shared'],
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'Content-Security-Policy', value: csp },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
        ],
      },
    ];
  },
};
export default nextConfig;
