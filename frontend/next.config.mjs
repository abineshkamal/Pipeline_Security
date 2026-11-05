/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "export",          // static export, served by FastAPI (PT_FRONTEND_DIR) or any static host
  images: { unoptimized: true },
  reactStrictMode: true,
  poweredByHeader: false,
};
export default nextConfig;
