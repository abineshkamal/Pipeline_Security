import "bootstrap/dist/css/bootstrap.min.css";
import "./globals.css";
import type { Metadata, Viewport } from "next";

export const metadata: Metadata = {
  title: "PipelineTrust",
  description: "AI-Powered CI/CD Security Assurance - OWASP Top 10 CI/CD Security Risks",
};
export const viewport: Viewport = { width: "device-width", initialScale: 1 };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" data-bs-theme="light">
      <body>{children}</body>
    </html>
  );
}
